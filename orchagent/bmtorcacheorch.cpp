#include <cassert>
#include <fstream>
#include <sstream>
#include <map>
#include <net/if.h>

#include "bmtorcacheorch.h"
#include "ipprefix.h"
#include "logger.h"
#include "swssnet.h"
#include "tokenize.h"
#include "bmt_common.h"

extern global_config_t g;

// extern sai_router_interface_api_t*  sai_router_intfs_api;
// extern sai_route_api_t*             sai_route_api;
extern sai_bmtor_api_t*                sai_bmtor_api;
extern sai_switch_api_t*               sai_switch_api;
extern sai_port_api_t*                 sai_port_api;
extern sai_tunnel_api_t*               sai_tunnel_api;
extern sai_bridge_api_t*               sai_bridge_api;
extern sai_vlan_api_t*                 sai_vlan_api;

extern PortsOrch *gPortsOrch;
extern sai_object_id_t gSwitchId;

BmToRCacheOrch::BmToRCacheOrch(DBConnector *db, vector<string> tableNames) :
        Orch(db, tableNames)
{
    SWSS_LOG_ENTER();
    gDPDKVlan = 3904;
    gVlansStart = 120;
    gTunnelId = SAI_NULL_OBJECT_ID;
    gVnetBitmap = 0xfff;
    gVhostTableSize = 256;
    dpdk_port = sai_get_port_id_by_front_port(2); // TODO - argument?
    bm_port_oid = sai_get_port_id_by_front_port(1); // TODO - why does vxlan tunnel need this as overlay interfacce?
    SWSS_LOG_NOTICE("DPDK port: 0x%lx. Ethernet0:0x%lx", dpdk_port, bm_port_oid);
}

sai_object_id_t BmToRCacheOrch::create_vlan(uint16_t vid) { //TODO: change to portsorch
  sai_attribute_t vlan_attr[1];
  vlan_attr[0].id = SAI_VLAN_ATTR_VLAN_ID;
  vlan_attr[0].value.u16 = vid;
  sai_object_id_t vlan_oid;
  sai_status_t status = sai_vlan_api->create_vlan(&vlan_oid, gSwitchId, 1, vlan_attr);
  SWSS_LOG_NOTICE("Vlan%d created. status = %d", vid, status);
  if (status == SAI_STATUS_SUCCESS)
    return vlan_oid;
  return SAI_NULL_OBJECT_ID;
}

sai_object_id_t BmToRCacheOrch::add_dpdk_vlan_member(sai_object_id_t vlan_oid) { //TODO: change to portsorch
  sai_attribute_t vlan_member_attr[3];
  vlan_member_attr[0].id = SAI_VLAN_MEMBER_ATTR_VLAN_ID;
  vlan_member_attr[0].value.oid = vlan_oid;
  vlan_member_attr[1].id = SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE;
  vlan_member_attr[1].value.s32 = SAI_VLAN_TAGGING_MODE_TAGGED;
  vlan_member_attr[2].id = SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID;
  vlan_member_attr[2].value.oid = gDpdkBirdgePort;
  sai_object_id_t vlan_member_oid;
  sai_status_t status = sai_vlan_api->create_vlan_member(&vlan_member_oid, gSwitchId, 3, vlan_member_attr);
  SWSS_LOG_NOTICE("Vlan member created. status = %d", status);
  if (status == SAI_STATUS_SUCCESS)
    return vlan_member_oid;
  return SAI_NULL_OBJECT_ID;
}

void BmToRCacheOrch::create_dpdk_bridge_port() {
  sai_attribute_t bridge_port_attr[3];
  bridge_port_attr[0].id = SAI_BRIDGE_PORT_ATTR_TYPE;
  bridge_port_attr[0].value.s32 = SAI_BRIDGE_PORT_TYPE_PORT;
  bridge_port_attr[1].id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
  bridge_port_attr[1].value.oid = getDPDKPort();
  bridge_port_attr[2].id = SAI_BRIDGE_PORT_ATTR_ADMIN_STATE;
  bridge_port_attr[2].value.booldata = true;
  sai_status_t status = sai_bridge_api->create_bridge_port(&gDpdkBirdgePort, gSwitchId, 3, bridge_port_attr);
  SWSS_LOG_NOTICE("DPDK bridge port created. status = %d", status);
}

void BmToRCacheOrch::InitDefaultEntries() {
  SWSS_LOG_ENTER();
  uint16_t vnet_bitmap = GetVnetBitmap(8); //TODO: build this from vnet peering list and vnet_intf
  sai_status_t status;
  sai_attribute_t table_peer_attr[3];
  table_peer_attr[0].id = SAI_TABLE_PEERING_ENTRY_ATTR_ACTION;
  table_peer_attr[0].value.s32 = SAI_TABLE_PEERING_ENTRY_ACTION_SET_VNET_BITMAP;
  table_peer_attr[1].id = SAI_TABLE_PEERING_ENTRY_ATTR_SRC_PORT;
  table_peer_attr[1].value.oid = bm_port_oid;
  table_peer_attr[2].id = SAI_TABLE_PEERING_ENTRY_ATTR_META_REG;
  table_peer_attr[2].value.u16 = vnet_bitmap;
  status = sai_bmtor_api->create_table_peering_entry(&peering_entry, gSwitchId, 3, table_peer_attr);
  if (status != SAI_STATUS_SUCCESS) {
      SWSS_LOG_ERROR("Failed to create table_peering entry");
      throw "BMToR initialization failure";
  }

  sai_attribute_t vhost_table_entry_attr[8];
  vhost_table_entry_attr[0].id = SAI_TABLE_VHOST_ENTRY_ATTR_ACTION;
  vhost_table_entry_attr[0].value.s32 = SAI_TABLE_VHOST_ENTRY_ACTION_TO_PORT;
  vhost_table_entry_attr[1].id = SAI_TABLE_VHOST_ENTRY_ATTR_PORT_ID;
  vhost_table_entry_attr[1].value.oid = dpdk_port;
  vhost_table_entry_attr[2].id = SAI_TABLE_VHOST_ENTRY_ATTR_IS_DEFAULT;
  vhost_table_entry_attr[2].value.booldata = true;

  // Patch. TODO: need to add condition in header - and remove this
  vhost_table_entry_attr[3].id = SAI_TABLE_VHOST_ENTRY_ATTR_PRIORITY; 
  vhost_table_entry_attr[3].value.u32 = 0;
  vhost_table_entry_attr[4].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_KEY;
  vhost_table_entry_attr[4].value.u32 = 0;
  vhost_table_entry_attr[5].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_MASK;
  vhost_table_entry_attr[5].value.u32 = 0;
  vhost_table_entry_attr[6].id = SAI_TABLE_VHOST_ENTRY_ATTR_DST_IP;
  vhost_table_entry_attr[6].value.u32 = 0;
  sai_object_id_t default_vhost_table_entry;
  status = sai_bmtor_api->create_table_vhost_entry(&default_vhost_table_entry, gSwitchId, 7, vhost_table_entry_attr);
  if (status != SAI_STATUS_SUCCESS) {
      SWSS_LOG_ERROR("Failed to create table_vhost default entry");
      throw "BMToR initialization failure";
  }
  setVhostEntry("default", default_vhost_table_entry);
}

sai_status_t BmToRCacheOrch::create_tunnel(IpAddress src_ip, uint32_t vni) {
  SWSS_LOG_ENTER();
  // Create bridge, tunnel and tunnel maps
  sai_status_t status;

  sai_attribute_t bridge_attr[1];
  bridge_attr[0].id = SAI_BRIDGE_ATTR_TYPE;
  bridge_attr[0].value.s32 = SAI_BRIDGE_TYPE_1D;
  status = sai_bridge_api->create_bridge(&gBridgeId, gSwitchId, 1, bridge_attr);
  printf("create_bridge. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    return status;

  sai_attribute_t tunnel_map_attr[2];
  sai_object_id_t tunnel_encap_map;
  sai_object_id_t tunnel_decap_map;
  sai_object_id_t tunnel_encap_map_entry;
  sai_object_id_t tunnel_term_table_entry;
  tunnel_map_attr[0].id = SAI_TUNNEL_MAP_ATTR_TYPE;
  tunnel_map_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI;
  tunnel_map_attr[1].id = SAI_TUNNEL_MAP_ATTR_MAP_TO_VALUE_LIST;
  tunnel_map_attr[1].value.tunnelmap.count = 0;
  tunnel_map_attr[1].value.tunnelmap.list = NULL;
  status = sai_tunnel_api->create_tunnel_map(&tunnel_encap_map, gSwitchId, 2, tunnel_map_attr);
  SWSS_LOG_NOTICE("create_tunnel_map (encap). status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    return status;

  tunnel_map_attr[0].id = SAI_TUNNEL_MAP_ATTR_TYPE;
  tunnel_map_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF;
  tunnel_map_attr[1].id = SAI_TUNNEL_MAP_ATTR_MAP_TO_VALUE_LIST;
  tunnel_map_attr[1].value.tunnelmap.count = 0;
  tunnel_map_attr[1].value.tunnelmap.list = NULL;
  status = sai_tunnel_api->create_tunnel_map(&tunnel_decap_map, gSwitchId, 2, tunnel_map_attr);
  SWSS_LOG_NOTICE("create_tunnel_map (decap). status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    return status;

  sai_attribute_t tunnel_map_entry_attr[4];
  tunnel_map_entry_attr[0].id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE;
  tunnel_map_entry_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI;
  tunnel_map_entry_attr[1].id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP;
  tunnel_map_entry_attr[1].value.oid = tunnel_encap_map;
  tunnel_map_entry_attr[2].id = SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE;
  tunnel_map_entry_attr[2].value.u32 = vni;
  tunnel_map_entry_attr[3].id = SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY;
  tunnel_map_entry_attr[3].value.oid = gBridgeId;
  status = sai_tunnel_api->create_tunnel_map_entry(&tunnel_encap_map_entry, gSwitchId, 4, tunnel_map_entry_attr);
  SWSS_LOG_NOTICE("create_tunnel_map_entry (encap). status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    return status;

  sai_attribute_t tunnel_attr[8];
  tunnel_attr[0].id = SAI_TUNNEL_ATTR_TYPE;
  tunnel_attr[0].value.s32 = SAI_TUNNEL_TYPE_VXLAN;
  tunnel_attr[1].id = SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE;
  tunnel_attr[1].value.oid = g.underlayIfId;
  tunnel_attr[2].id = SAI_TUNNEL_ATTR_OVERLAY_INTERFACE;
  tunnel_attr[2].value.oid = bm_port_oid;
  tunnel_attr[3].id = SAI_TUNNEL_ATTR_DECAP_ECN_MODE;
  tunnel_attr[3].value.s32 = SAI_TUNNEL_DECAP_ECN_MODE_USER_DEFINED;
  tunnel_attr[4].id = SAI_TUNNEL_ATTR_DECAP_MAPPERS;
  tunnel_attr[4].value.objlist.count = 1;
  tunnel_attr[4].value.objlist.list = &tunnel_decap_map;
  tunnel_attr[5].id = SAI_TUNNEL_ATTR_ENCAP_ECN_MODE;
  tunnel_attr[5].value.s32 = SAI_TUNNEL_ENCAP_ECN_MODE_USER_DEFINED;
  tunnel_attr[6].id = SAI_TUNNEL_ATTR_ENCAP_MAPPERS;
  tunnel_attr[6].value.objlist.count = 1;
  tunnel_attr[6].value.objlist.list = &tunnel_encap_map;
  tunnel_attr[7].id = SAI_TUNNEL_ATTR_ENCAP_SRC_IP;
  tunnel_attr[7].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
  tunnel_attr[7].value.ipaddr.addr.ip4 = src_ip.getIp().ip_addr.ipv4_addr;
  status = sai_tunnel_api->create_tunnel(&gTunnelId, gSwitchId, 8, tunnel_attr);
  SWSS_LOG_NOTICE("create_tunnel ip=0x%x. status = %d\n", ntohl(src_ip.getIp().ip_addr.ipv4_addr), status);
  if (status != SAI_STATUS_SUCCESS)
    return status;

  // Create termination entry for host at switch vtep
  SWSS_LOG_NOTICE("sai_tunnel_id = 0x%lx\n", gTunnelId);
  sai_attribute_t tunnel_term_table_entry_attr[5];
  tunnel_term_table_entry_attr[0].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID;
  tunnel_term_table_entry_attr[0].value.oid = g.virtualRouterId;
  tunnel_term_table_entry_attr[1].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE;
  tunnel_term_table_entry_attr[1].value.s32 = SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP;
  tunnel_term_table_entry_attr[2].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP;
  tunnel_term_table_entry_attr[2].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
  tunnel_term_table_entry_attr[2].value.ipaddr.addr.ip4 = src_ip.getIp().ip_addr.ipv4_addr;
  tunnel_term_table_entry_attr[3].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID;
  tunnel_term_table_entry_attr[3].value.oid = gTunnelId;
  tunnel_term_table_entry_attr[4].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE;
  tunnel_term_table_entry_attr[4].value.s32 = SAI_TUNNEL_TYPE_VXLAN;
  status = sai_tunnel_api->create_tunnel_term_table_entry(&tunnel_term_table_entry, gSwitchId, 5, tunnel_term_table_entry_attr);
  SWSS_LOG_NOTICE("create_tunnel_term_entry. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    return status;

  return SAI_STATUS_SUCCESS;
}

void BmToRCacheOrch::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    if (!gPortsOrch->isInitDone())
    {
        return;
    }

    string table_name = consumer.getTableName();
    if (table_name == "VNET_ROUTE_TUNNEL_TABLE") {
      doVnetRouteTunnelTask(consumer);
    } else if (table_name == "VNET_ROUTE_TABLE") {
      doVnetRouteTask(consumer);
    } else if (table_name == "VNET") {
      doVnetTask(consumer);
    } else if (table_name == "VNET_INTF") {
      doVnetIntfTask(consumer);
    } else if (table_name == "VXLAN_TUNNEL") {
      doVxlanTunnelTask(consumer);
    }
}

void BmToRCacheOrch::doVnetRouteTask(Consumer &consumer) {
  SWSS_LOG_ENTER();
}

void BmToRCacheOrch::doVnetTask(Consumer &consumer) {
  SWSS_LOG_ENTER();
  auto it = consumer.m_toSync.begin();
  while (it != consumer.m_toSync.end()) {
    string op = kfvOp(it->second);
    string vnet_name = kfvKey(it->second);
    string vxlan_tunnel;
    string vni_str;
    for (auto i : kfvFieldsValues(it->second)) {
            if (fvField(i) == "vxlan_tunnel")
                vxlan_tunnel = fvValue(i);
            if (fvField(i) == "vxlanid")
                vni_str = fvValue(i);
        }
    uint32_t vni = stoi(vni_str);
    SWSS_LOG_NOTICE("vnet_name %s. vxlan_tunnel name %s. vni_str %s, vni %d", vnet_name.c_str(), vxlan_tunnel.c_str(), vni_str.c_str(), vni);
    if (op == SET_COMMAND) {
      IpAddress src_ip;
      getTunnelIP(vxlan_tunnel, src_ip);
      create_tunnel(src_ip, vni);
    }
    it = consumer.m_toSync.erase(it);
  }
}

void BmToRCacheOrch::doVnetIntfTask(Consumer &consumer) {
  SWSS_LOG_ENTER();
  auto it = consumer.m_toSync.begin();
  while (it != consumer.m_toSync.end()) {
    string op = kfvOp(it->second);
    string key = kfvKey(it->second);
    string vnet_name;
    vector<string> keys = tokenize(kfvKey(it->second), ':');
    string if_name = keys[0];
    string bm_ip_prefix_str = keys[1];
    IpPrefix bm_ip_prefix(bm_ip_prefix_str);
    for (auto i : kfvFieldsValues(it->second)) {
            if (fvField(i) == "vnet_name")
                vnet_name = fvValue(i);
        }
    sai_object_id_t port_id = sai_get_port_id_by_alias(if_name);
    SWSS_LOG_NOTICE("Vnet name %s, ifname %s,port_oid 0x%lx ipprefix %s", vnet_name.c_str(), if_name.c_str(), port_id, bm_ip_prefix_str.c_str());
    if (op == SET_COMMAND) {
        sai_status_t status;
        sai_attribute_t pvid_attr;
        uint16_t vid = get_new_vlan();
        pvid_attr.id = SAI_PORT_ATTR_PORT_VLAN_ID;
        pvid_attr.value.u16 = vid;
        status = sai_port_api->set_port_attribute(port_id, &pvid_attr);
        SWSS_LOG_NOTICE("Set port pvid %d. status %d\n", pvid_attr.value.u16, status);

        sai_object_id_t vlan_oid = create_vlan(vid);
        // TODO - check for NULL
        // sai_object_id_t dpdk_vlan_member = add_dpdk_vlan_member(vlan_oid);
        add_dpdk_vlan_member(vlan_oid);
        // TODO - check for NULL
        setVnetVlan(vnet_name, vlan_oid);
 	sai_object_id_t router_entry_id;	
	sai_attribute_t vhost_table_entry_attr[6];
	uint32_t vni = 10; // TODO: get this from VNET (store vnet_name->vni map)
	uint16_t vnet_bitmap = GetVnetBitmap(vni);
  	uint32_t offset = GetFreeOffset();
	if (offset == gVhostTableSize)
		SWSS_LOG_ERROR("couldn't create router entry, since cache is full");
	vhost_table_entry_attr[0].id = SAI_TABLE_VHOST_ENTRY_ATTR_ACTION;
	vhost_table_entry_attr[0].value.s32 = SAI_TABLE_VHOST_ENTRY_ACTION_TO_ROUTER;
	vhost_table_entry_attr[1].id = SAI_TABLE_VHOST_ENTRY_ATTR_PRIORITY;
	vhost_table_entry_attr[1].value.u32 = offset; // Todo - manage this in mlnx_sai
	vhost_table_entry_attr[2].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_KEY;
	vhost_table_entry_attr[2].value.u16 = vnet_bitmap;
	vhost_table_entry_attr[3].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_MASK;
	vhost_table_entry_attr[3].value.u16 = vnet_bitmap;
	vhost_table_entry_attr[4].id = SAI_TABLE_VHOST_ENTRY_ATTR_DST_IP;
	vhost_table_entry_attr[4].value.ipaddr.addr.ip4 = bm_ip_prefix.getIp().getIp().ip_addr.ipv4_addr;
	vhost_table_entry_attr[4].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
	vhost_table_entry_attr[5].id = SAI_TABLE_VHOST_ENTRY_ATTR_VR_ID;
	vhost_table_entry_attr[5].value.oid = g.virtualRouterId;
	status = sai_bmtor_api->create_table_vhost_entry(&router_entry_id, gSwitchId, 6, vhost_table_entry_attr);
	if (status == SAI_STATUS_SUCCESS) {
	  used_offsets[router_entry_id] = offset;
	  setVhostEntry(key, router_entry_id);
	} else {
	  SWSS_LOG_ERROR("Error creating router entry. status = %d", status);
	}
    }
    it = consumer.m_toSync.erase(it);
  }
}

void BmToRCacheOrch::doVxlanTunnelTask(Consumer &consumer) {
  SWSS_LOG_ENTER();

  auto it = consumer.m_toSync.begin();
  while (it != consumer.m_toSync.end()) {
    InitDefaultEntries();  //TODO - this should move to some init
    create_dpdk_bridge_port(); //TODO - this should move to some init
    string op = kfvOp(it->second);
    string key = kfvKey(it->second);
    string src_ip_str;
    for (auto i : kfvFieldsValues(it->second)) {
            if (fvField(i) == "src_ip")
                src_ip_str = fvValue(i);
        }
    IpAddress src_ip(src_ip_str);
    SWSS_LOG_NOTICE("tunnel name %s. src_ip_str %s, ip 0x%x", key.c_str(), src_ip_str.c_str(), ntohl(src_ip.getIp().ip_addr.ipv4_addr));
    if (op == SET_COMMAND) {
      setTunnelIP(key, src_ip);
    }
    it = consumer.m_toSync.erase(it);
  }
}

void BmToRCacheOrch::doVnetRouteTunnelTask(Consumer &consumer) { //TODO - insert to DPDK
    // SWSS_LOG_ENTER();
    // auto it = consumer.m_toSync.begin();
    // while (it != consumer.m_toSync.end()) {
    //     KeyOpFieldsValuesTuple t = it->second;
    //     vector<string> keys = tokenize(kfvKey(t), ':');
    //     string vnet_name(keys[0]);
    //     for (std::vector<string>::iterator it_keys = keys.begin(); it_keys < keys.end(); ++it_keys) {
    //         SWSS_LOG_NOTICE("keys[%d] = %s", (int) (it_keys - keys.begin()), it_keys->c_str());
    //     }
    //     string endpoint;
    //     IpPrefix overlay_dip_prefix(keys[keys.size()-1]);
    //     for (auto i : kfvFieldsValues(t)) {
    //         if (fvField(i) == "endpoint")                endpoint = fvValue(i);
    //     }
    //     string op = kfvOp(t);
    //     string key = kfvKey(t);
    //     IpAddress underlay_dip(endpoint);
    //     sai_status_t status;
    //     uint32_t vni = 8; //Get this from Vnet name
    //     sai_object_id_t vhost_entry;
    //     if (op == SET_COMMAND) {
    //         SWSS_LOG_NOTICE("create VNET_ROUTE_TUNNEL_TABLE. switchId = 0x%lx", switchId);
    //         SWSS_LOG_NOTICE("vnet %s. enpoint %s. underlay_dip 0x%x", vnet_name.c_str(), endpoint.c_str(), htonl(underlay_dip.getIp().ip_addr.ipv4_addr));
    //         status = CreateVhostEntry(&vhost_entry, underlay_dip, overlay_dip_prefix.getIp(), vni); 
    //         if (status != SAI_STATUS_SUCCESS) {
    //             SWSS_LOG_ERROR("Failed to add table_vhost entry");
    //             throw "BMToR vhost entry addition failure";
    //         }
    //         setVhostEntry(key, vhost_entry);
    //     } else if (op == DEL_COMMAND) {
    //         SWSS_LOG_NOTICE("REMOVE VNET_ROUTE_TUNNEL_TABLE");
    //         getVhostEntry(key, vhost_entry);
    //         status = sai_bmtor_api->remove_table_vhost_entry(vhost_entry);
    //         if (status != SAI_STATUS_SUCCESS) {
    //             SWSS_LOG_ERROR("Failed to remove table_peering entry");
    //             throw "BMToR vhost entry removal failure";
    //         }
    //     }
    //     it = consumer.m_toSync.erase(it);
    // }
}

sai_status_t BmToRCacheOrch::RemoveTableVhost(sai_object_id_t entry_id) {
  SWSS_LOG_ENTER();
  sai_status_t status = sai_bmtor_api->remove_table_vhost_entry(entry_id);
  SWSS_LOG_NOTICE("removed table vhost entry status = %d", status);
  if (status != SAI_STATUS_SUCCESS)
    return status;
  if (removeVhostEntry(entry_id)) {
    return SAI_STATUS_SUCCESS;
  } else {
    return SAI_STATUS_FAILURE;
  }

}

uint32_t BmToRCacheOrch::GetFreeOffset() { // TODO - this should be managed inside mlnx_sai
  std::map<sai_object_id_t, uint32_t>::iterator it; 
  for (uint32_t i = 0; i < gVhostTableSize; i++) {
    for (it = used_offsets.begin(); it != used_offsets.end(); ++it) {
      if (it->second == i)
        break;
    }
    if (it == used_offsets.end()) {
      return i;
    }
  }
  SWSS_LOG_ERROR("Tried to add entry, but no free offset is available");
  return gVhostTableSize;
}

sai_status_t BmToRCacheOrch::CreateVhostEntry(sai_object_id_t *entry_id, IpAddress underlay_dip, IpAddress overlay_dip, uint32_t vni) {
  // TODO - create key and add to vhosy_entries map in here
  SWSS_LOG_ENTER();
  sai_attribute_t vhost_table_entry_attr[8];
  uint16_t vnet_bitmap = GetVnetBitmap(vni);
  std::string key = "Vnet_" + to_string(vni) + ":" +  overlay_dip.to_string() + "/32";
  SWSS_LOG_NOTICE("[debug] Looking up key %s", key.c_str());
  if (getVhostEntry(key, *entry_id)) {
    SWSS_LOG_NOTICE("Tried to insert an existing entry. returns existing entry");
    return SAI_STATUS_FAILURE;
  }
  uint32_t offset = GetFreeOffset();
  if (offset == gVhostTableSize)
    return SAI_STATUS_FAILURE;
  vhost_table_entry_attr[0].id = SAI_TABLE_VHOST_ENTRY_ATTR_ACTION;
  vhost_table_entry_attr[0].value.s32 = SAI_TABLE_VHOST_ENTRY_ACTION_TO_TUNNEL;
  vhost_table_entry_attr[1].id = SAI_TABLE_VHOST_ENTRY_ATTR_PRIORITY;
  vhost_table_entry_attr[1].value.u32 = offset; // Todo - manage this in mlnx_sai
  vhost_table_entry_attr[2].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_KEY;
  vhost_table_entry_attr[2].value.u16 = vnet_bitmap;
  vhost_table_entry_attr[3].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_MASK;
  vhost_table_entry_attr[3].value.u16 = vnet_bitmap;
  vhost_table_entry_attr[4].id = SAI_TABLE_VHOST_ENTRY_ATTR_DST_IP;
  vhost_table_entry_attr[4].value.ipaddr.addr.ip4 = overlay_dip.getIp().ip_addr.ipv4_addr;
  vhost_table_entry_attr[4].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
  vhost_table_entry_attr[5].id = SAI_TABLE_VHOST_ENTRY_ATTR_TUNNEL_ID;
  vhost_table_entry_attr[5].value.oid = GetTunnelID();
  vhost_table_entry_attr[6].id = SAI_TABLE_VHOST_ENTRY_ATTR_UNDERLAY_DIP;
  vhost_table_entry_attr[6].value.ipaddr.addr.ip4 = underlay_dip.getIp().ip_addr.ipv4_addr;
  vhost_table_entry_attr[6].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
  vhost_table_entry_attr[7].id = SAI_TABLE_VHOST_ENTRY_ATTR_BRIDGE_ID;
  vhost_table_entry_attr[7].value.oid = gBridgeId;
  sai_status_t status = sai_bmtor_api->create_table_vhost_entry(entry_id, gSwitchId, 8, vhost_table_entry_attr);
  if (status == SAI_STATUS_SUCCESS) {
    used_offsets[*entry_id] = offset;
    setVhostEntry(key, *entry_id);
  }
  return status;
}

void BmToRCacheOrch::setVhostEntry(std::string key, sai_object_id_t entry_id)
{
    vhost_entries[key] = entry_id;
}

bool BmToRCacheOrch::getVhostEntry(std::string key, sai_object_id_t &entry_id)
{
    SWSS_LOG_ENTER();

    if (vhost_entries.find(key) == vhost_entries.end())
    {
        return false;
    }
    else
    {
        entry_id = vhost_entries[key];
        return true;
    }
}
void BmToRCacheOrch::RemoveOffset(sai_object_id_t entry_id) {
  std::map<sai_object_id_t, uint32_t>::iterator it = used_offsets.find(entry_id);
  if (it != used_offsets.end()) {
    used_offsets.erase(it);
  }
}

bool BmToRCacheOrch::removeVhostEntry(sai_object_id_t entry_id) {
  for (map<std::string, sai_object_id_t>::iterator it = vhost_entries.begin(); it != vhost_entries.end(); ++it) {
    if (it->second == entry_id) {
      vhost_entries.erase(it);
      RemoveOffset(entry_id);
      return true;
    }
  }
  return false;
}

void BmToRCacheOrch::setTunnelIP(std::string key, IpAddress IP)
{
    tunnel_ip_map[key] = IP;
}

bool BmToRCacheOrch::getTunnelIP(std::string key, IpAddress &IP)
{
    SWSS_LOG_ENTER();

    if (tunnel_ip_map.find(key) == tunnel_ip_map.end())
    {
        return false;
    }
    else
    {
        IP = tunnel_ip_map[key];
        return true;
    }
}

void BmToRCacheOrch::setVnetVlan(std::string key, sai_object_id_t Vlan)
{
    vnet_vlan_map[key] = Vlan;
}

bool BmToRCacheOrch::getVnetVlan(std::string key, sai_object_id_t &Vlan)
{
    SWSS_LOG_ENTER();

    if (vnet_vlan_map.find(key) == vnet_vlan_map.end())
    {
        return false;
    }
    else
    {
        Vlan = vnet_vlan_map[key];
        return true;
    }
}

uint16_t BmToRCacheOrch::get_vid_from_vlan(sai_object_id_t vlan_oid) {
  sai_attribute_t vlan_attr[1];
  vlan_attr[0].id = SAI_VLAN_ATTR_VLAN_ID;
  sai_vlan_api->get_vlan_attribute(vlan_oid, 1, vlan_attr);
  return vlan_attr[0].value.u16;
}

bool BmToRCacheOrch::is_vlan_used(uint16_t vid) {
  for (map<std::string, sai_object_id_t>::iterator it = vnet_vlan_map.begin(); it != vnet_vlan_map.end(); ++it) {
    if (vid == get_vid_from_vlan(it->second)) {
      return true;
    }
  }
  return false;
}

uint16_t BmToRCacheOrch::get_new_vlan() {
  for (uint16_t i=gVlansStart; i<4096; i++) {
    if (!is_vlan_used(i)) {
      return i;
    }
  }
  return 0;
}

sai_object_id_t BmToRCacheOrch::sai_get_port_id_by_alias(std::string alias) {
  Port port;
  gPortsOrch->getPort(alias, port);
  switch (port.m_type) {
    case Port::PHY:
      return port.m_port_id;
    case Port::LAG:
      return port.m_lag_id;
    default:
      return SAI_NULL_OBJECT_ID;
  }
}

string BmToRCacheOrch::getDPDKPortIF() {
  Port port;
  if (gPortsOrch->getPort(dpdk_port, port)) 
    return port.m_alias;
  return "";
}

sai_object_id_t BmToRCacheOrch::getDPDKPort() {
  return dpdk_port;
}

uint16_t BmToRCacheOrch::GetVnetBitmap(uint32_t vni) {
  return gVnetBitmap;
}

sai_object_id_t BmToRCacheOrch::GetTunnelID() {
  return gTunnelId;
}

sai_object_id_t BmToRCacheOrch::sai_get_port_id_by_front_port(uint32_t hw_port) {
  sai_object_id_t new_objlist[32]; //TODO change back to getting from switch
  sai_attribute_t sai_attr;
  sai_attr.id = SAI_SWITCH_ATTR_PORT_NUMBER;
  uint32_t max_ports = 32;

  sai_attr.id = SAI_SWITCH_ATTR_PORT_LIST;
  sai_attr.value.objlist.count = max_ports;
  sai_attr.value.objlist.list = &new_objlist[0];
  sai_switch_api->get_switch_attribute(gSwitchId, 1, &sai_attr);

  sai_attribute_t hw_lane_list_attr;
  uint32_t i;
  for (i = 0; i < max_ports; i++)
  {
    uint32_t hw_port_list[4];
    hw_lane_list_attr.id = SAI_PORT_ATTR_HW_LANE_LIST;
    hw_lane_list_attr.value.u32list.list = &hw_port_list[0];
    hw_lane_list_attr.value.u32list.count = 4;
    sai_port_api->get_port_attribute(sai_attr.value.objlist.list[i], 1,
                                 &hw_lane_list_attr);
    if (hw_port_list[0] == ((hw_port - 1) * 4))
    {
      return sai_attr.value.objlist.list[i];
    }
  }
  printf("didn't find port");
  return -1;
}
