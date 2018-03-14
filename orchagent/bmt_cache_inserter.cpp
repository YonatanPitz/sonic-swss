extern "C" {
#include "sai.h"
#include "saistatus.h"
#include "saihostif.h"
#include "saisamplepacket.h"
}
#include <algorithm>
#include <arpa/inet.h>
#include "saihelper.h"
#include <fstream>
#include <iostream>
#include <csignal>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <vector>
#include <set>
#include <list>
#include <map>
#include <mutex>
#include <thread>
#include <pcap.h>
#include <chrono>
#include "bmt_orch_constants.h"
#include "bmt_common.h"
#include "bmt_cache_inserter.h"
#include "bmt_cache_debug.h"
#include "bmtorcacheorch.h"
#include "logger.h"
#include <unistd.h>
#include <string.h>
#include "portsorch.h"
#include "ipprefix.h"
#include "saiserialize.h"

#include <linux/if_packet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <ctime>
#include <cstdlib>
#include <bits/stdc++.h>
#include "bmt_common.h"
extern global_config_t g;

using namespace std;
extern sai_hostif_api_t *sai_hostif_api;
extern sai_samplepacket_api_t *sai_samplepacket_api;
extern sai_port_api_t *sai_port_api;
extern sai_switch_api_t *sai_switch_api;
extern sai_bmtor_api_t *sai_bmtor_api;

//mutex cout_mutex;
extern PortsOrch *gPortsOrch;
extern BmToRCacheOrch *gBmToRCacheOrch;

typedef struct bmt_dpdk_pkt_t {
    uint32_t underlay_dip;
    uint32_t overlay_dip;
    uint32_t vni;
} bmt_dpdk_pkt_t;

struct bmt_dpdk_pkt_compare_t {
    bool operator()(const bmt_dpdk_pkt_t &pkt1, const bmt_dpdk_pkt_t &pkt2) const
    {
      return (pkt1.overlay_dip == pkt2.overlay_dip)
          && (pkt1.vni == pkt2.vni);
    }
};

typedef struct bmt_vhost_entry_t { //TODDO - change to map<offset:entry_id>?
    bool valid;
    sai_object_id_t entry_id;
    uint32_t overlay_dip;
    uint32_t underlay_dip;
    uint32_t vni;
}bmt_vhost_entry_t;


typedef struct bmt_vhost_table_t {
    bmt_vhost_entry_t   entry[VHOST_TABLE_SIZE];
    uint32_t            used_entries=0;
    mutex               free_offset_mutex;
    vector<uint32_t>    free_offsets; // TODO implement cache evac
} bmt_vhost_table_t;

typedef std::pair<uint32_t, uint32_t> DpdkPacketKey;    // vni, overlay_ip
typedef std::pair<uint32_t, uint64_t> DpdkPacketValue;  // underlay_ip, count
typedef std::map<DpdkPacketKey, DpdkPacketValue> DpdkPacketMap;

/* Global variables */
extern sai_object_id_t gSwitchId;
extern sai_object_id_t dpdk_port;
sai_object_id_t samplepacketOid;
sai_object_id_t samplepackettrapOid;
sai_object_id_t trapGroupOid;
sai_object_id_t hostifOid;
sai_object_id_t hostif_table_entryOid;
sai_object_id_t trapgroupOid;
bmt_vhost_table_t vhost_table;
bmtCacheManager cacheManager;
DBConnector *countersDb = 0;
Table *countersTable = 0;
std::mutex counter_mutex;

sai_status_t bmt_get_free_offset(uint32_t &offset){
    if (vhost_table.used_entries == (VHOST_TABLE_SIZE-1)){
        //TODO take from free list when cache evac is working.
        if (vhost_table.free_offsets.size()>0){
            offset = vhost_table.free_offsets.back();
            // vhost_table.free_offsets.pop_back();  // we pop only if the rule was actually inserted.
            SWSS_LOG_NOTICE("[inserter] INFO: cache full, replacing chace entry: %u", offset);
        }
        else
            SWSS_LOG_NOTICE("[inserter] WARNING, no free entries");
        return SAI_STATUS_FAILURE;
    }
    else{
        SWSS_LOG_NOTICE("[inserter] INFO: cache has unused entries, using entry %u/%u", vhost_table.used_entries, VHOST_TABLE_SIZE-1);
        offset = vhost_table.used_entries;
        // vhost_table.used_entries++; // we inc only if the rule was actually inserted.
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t bmt_cache_insert_vhost_entry(uint32_t overlay_dip, uint32_t underlay_dip, uint32_t vni){
    lock_guard<mutex> guard(vhost_table.free_offset_mutex);
    uint32_t offset;
    sai_status_t status = bmt_get_free_offset(offset);
    if (status != SAI_STATUS_SUCCESS) 
        return status;
    SWSS_LOG_NOTICE("Vhost Entry creation. underlay dip 0x%x overlay_dip 0x%x. vni %d", underlay_dip, overlay_dip, vni);
    sai_object_id_t entry_id;
    status = gBmToRCacheOrch->CreateVhostEntry(&entry_id, IpAddress(htonl(underlay_dip)), IpAddress(htonl(overlay_dip)), vni);
    if (status != SAI_STATUS_SUCCESS){
        SWSS_LOG_ERROR("[inserter] ERROR: failed to insert vhost rule, rv: %u", status);
        return status;
        
    }

    if (vhost_table.used_entries == (VHOST_TABLE_SIZE-1)){
        vhost_table.free_offsets.pop_back();
    } else {
        vhost_table.used_entries++;
    }
    vhost_table.entry[offset].overlay_dip = overlay_dip;
    vhost_table.entry[offset].underlay_dip = underlay_dip;
    vhost_table.entry[offset].vni = vni;
    vhost_table.entry[offset].entry_id = entry_id;
    vhost_table.entry[offset].valid = true;
    return SAI_STATUS_SUCCESS;
}

// sai_status_t bmt_parse_packet(const u_char *buf, sai_size_t buffer_size, bmt_dpdk_pkt_t *pkt){
void bmt_parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buf) {
    //--------------------------------------
    // netdev encap via ip4 packet: so vxlan is shifted:
    // L2 (0-13) => L3 (14-33) => udp (34-41) => vxlan (42-49) => L2 (50-63) => L3 (64-83)
    sai_size_t buffer_size = header->len;
    // SWSS_LOG_NOTICE("[inserter] [recv] parsing packet of len %d", header->len);
    // pkt.valid = false;
    DpdkPacketMap *pkt_map = (DpdkPacketMap *) args;
    uint16_t etherType[2];
    uint8_t vxlan_flags;
    uint8_t inner_ipv4_ver;
    uint8_t outer_ipv4_ver;
    if (buffer_size >= 84){ // TODO should be 84
        etherType[0]   = (uint16_t)(((uint16_t)buf[12]<<8)|(uint16_t)buf[13]); // outer L2 etherType (tagged)
        outer_ipv4_ver = (uint8_t)(buf[14]>>4);
        vxlan_flags    = (uint8_t) buf[42]; // inner L2 etherType
        etherType[1]   = (uint16_t)(((int)buf[62]<<8)|(int)buf[63]); // inner etherType
        inner_ipv4_ver = (uint8_t)(buf[64]>>4);      
        if(
                etherType[0]    == TYPE_IPV4 &&
                etherType[1]    == TYPE_IPV4 &&
                vxlan_flags     == 8         &&
                outer_ipv4_ver  == 4         &&
                inner_ipv4_ver  == 4
        )
        {

            uint32_t vni = (((uint32_t)buf[46])<<16) | (((uint32_t)buf[47])<<8) | ((uint32_t)buf[48]);
            uint32_t underlay_dip = ((uint32_t)buf[30]<<24) | ((uint32_t)buf[31]<<16) | ((uint32_t)buf[32]<<8) | ((uint32_t)buf[33]);
            uint32_t overlay_dip = ((uint32_t)buf[80]<<24) | ((uint32_t)buf[81]<<16) | ((uint32_t)buf[82]<<8) | ((uint32_t)buf[83]);
            uint32_t len = ((((uint32_t)buf[16])<<8) | ((uint32_t)buf[17]));
            // SWSS_LOG_NOTICE("[inserter] [recv] packet parsed successfully:     vni= %ul.  overlay  ip=%d.%d.%d.%d. underlay ip=%d.%d.%d.%d",vni, int(buf[80]),int(buf[81]),int(buf[82]),int(buf[83]), int(buf[30]),int(buf[31]),int(buf[32]),int(buf[33]));
            DpdkPacketKey pkt_pair = std::make_pair(vni, overlay_dip);
            DpdkPacketMap::iterator it = pkt_map->find(pkt_pair);
            if (it != pkt_map->end())
                it->second.second += len;
            else
                (*pkt_map)[pkt_pair]=std::make_pair(underlay_dip, len);
//            for (it = pkt_map->begin(); it != pkt_map->end(); ++it) {
//                SWSS_LOG_NOTICE("pkt 0x%x (ovrly) @ vni %d.  cnt = %d (%d)", it->first.second, it->first.first, it->second.second, (*pkt_map)[pkt_pair].second);
//            }
        }
        else {
            SWSS_LOG_NOTICE("[inserter] [recv] non-vxlan packet");
        }
    }
    else {
        SWSS_LOG_NOTICE("[inserter] [recv] short packet");
    }
}

sai_status_t bmt_get_port_vect_from_vni(uint32_t vni, uint16_t* port_vect){
    // TODO implement
    *port_vect = (uint16_t) 0xfff;
    return SAI_STATUS_SUCCESS;
}

int bmt_init_dpdk_traffic_sampler(){
    //lock_guard<mutex> guard(cout_mutex);
    sai_status_t status;
    sai_attribute_t attr;

    /* create packet sampler */
    vector<sai_attribute_t> packetsampler_attrs;
    attr.id = SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE;
    attr.value.u32 = PACKETS_PER_SAMPLE;
    packetsampler_attrs.push_back(attr);

    attr.id = SAI_SAMPLEPACKET_ATTR_TYPE;
    attr.value.s32 = SAI_SAMPLEPACKET_TYPE_SLOW_PATH; // sample each packet
    packetsampler_attrs.push_back(attr);

    attr.id = SAI_SAMPLEPACKET_ATTR_MODE;
    attr.value.s32 = SAI_SAMPLEPACKET_MODE_EXCLUSIVE; // sample each packet
    packetsampler_attrs.push_back(attr);

    status = sai_samplepacket_api->create_samplepacket(&samplepacketOid,gSwitchId,(uint32_t)packetsampler_attrs.size(),packetsampler_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("[inserter] Failed to create samplepacket, rv: %u", status);
        return (6);
    }
    SWSS_LOG_NOTICE("[inserter] Created samplepacket");


    /* BIND to ingress dpdk port */
    attr.id = SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE;
    attr.value.oid=samplepacketOid;
    status = sai_port_api->set_port_attribute(dpdk_port,&attr);
    if (status != SAI_STATUS_SUCCESS){
        SWSS_LOG_ERROR("[inserter] Failed to bind packet sampler to port, rv: %u", status);
        return (5);   
    }
#if 0
    /* create hostif */
    vector<sai_attribute_t> hostif_attrs;
    attr.id = SAI_HOSTIF_ATTR_TYPE;
    attr.value.s32 = SAI_HOSTIF_TYPE_FD;
    hostif_attrs.push_back(attr);

    // attr.id = SAI_HOSTIF_ATTR_OPER_STATUS; // TODO, needed?
    // attr.value.booldata = true;
    // hostif_attrs.push_back(attr);

    //attr.id = SAI_HOSTIF_ATTR_QUEUE; 0 for now

    status = sai_hostif_api->create_hostif(&hostifOid,gSwitchId,(uint32_t)hostif_attrs.size(),hostif_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("[inserter] Failed to create hostif, rv: %u", status);
        return (4);
    }
    SWSS_LOG_ERROR("[inserter] Created hostif");
#endif
    /* Use hostif created by portsorch */
    Port port;
    if (!gPortsOrch->getPort(dpdk_port, port))
    {
        SWSS_LOG_ERROR("[inserter] Failed to get hostif");
        return (4);
    }

    hostifOid = port.m_hif_id;
    SWSS_LOG_NOTICE("[inserter] Got hostif");

    /* create trap group for samplepacket trap */
    vector<sai_attribute_t> hostifTrapGroup_attrs;
    // attr.id = SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE;
    // attr.value.u32 = 100; // TODO !
    // hostifTrapGroup_attrs.push_back(attr);
    // attr.id = SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER;
    status = sai_hostif_api->create_hostif_trap_group(&trapGroupOid,gSwitchId,(uint32_t)hostifTrapGroup_attrs.size(),hostifTrapGroup_attrs.data());
    if (status != SAI_STATUS_SUCCESS){
        SWSS_LOG_ERROR("[inserter] Failed to creat Hostif Trap group, rv:%d", status);
        return (3);
    }
    SWSS_LOG_NOTICE("[inserter] Created hostif trap group");


	/* create trap for samplepacket action */
    vector<sai_attribute_t> trap_attrs;

    attr.id = SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE;
    attr.value.s32 = SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET;
    trap_attrs.push_back(attr);

    attr.id = SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP;
    attr.value.oid = trapGroupOid;
    trap_attrs.push_back(attr);

    attr.id = SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION;
    attr.value.s32 = SAI_PACKET_ACTION_LOG; //sai_packet_action_t
    trap_attrs.push_back(attr);

    attr.id = SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY;
    attr.value.u32 = SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY + 5;
    trap_attrs.push_back(attr);

        //  TODO trap only dpdk port ingress
        // attr.id = SAI_HOSTIF_TRAP_ATTR_EXCLUDE_PORT_LIST;
        // attr.objlist.count = ;
        // attr.objlist.list  = ;

    status = sai_hostif_api->create_hostif_trap(&samplepackettrapOid, gSwitchId, (uint32_t)trap_attrs.size(), trap_attrs.data());
    if (status != SAI_STATUS_SUCCESS){
        SWSS_LOG_ERROR("[inserter] Failed to create samplepacket Hostif Trap, rv: %d", status);
        return (2);
    }
    SWSS_LOG_NOTICE("[inserter] Created hostif samplepacket trap for action_log");

    /* create hostif table entry */
    vector<sai_attribute_t> hostif_table_entry_attrs;

    attr.id = SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE;
    attr.value.s32 = SAI_HOSTIF_TABLE_ENTRY_TYPE_TRAP_ID;
    hostif_table_entry_attrs.push_back(attr);

    attr.id = SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID;
    attr.value.oid = samplepackettrapOid;
    hostif_table_entry_attrs.push_back(attr);

    attr.id = SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE;
    attr.value.s32 = SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_PHYSICAL_PORT;
    hostif_table_entry_attrs.push_back(attr);
#if 0
    attr.id = SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF;
    attr.value.oid = hostifOid;
    hostif_table_entry_attrs.push_back(attr);
#endif

    status = sai_hostif_api->create_hostif_table_entry(
        &hostif_table_entryOid, gSwitchId, (uint32_t)hostif_table_entry_attrs.size(), hostif_table_entry_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("[inserter] Failed to create default host interface table, rv: %d", status);
        return (1);
    }
    SWSS_LOG_NOTICE("[inserter] Create default host interface table");

    SWSS_LOG_NOTICE("[inserter] sampler init success.");
    return 0;
}



int bmt_deinit_dpdk_traffic_sampler(int init_status){
    //lock_guard<mutex> guard(cout_mutex);
    sai_status_t status = SAI_STATUS_SUCCESS;
    // TODO remove all entries / delete table and recreate with default entry only !!!!!!
    if (vhost_table.used_entries>0){
        for(uint32_t i=0; i<vhost_table.used_entries;i++){
// TODO
            // status = remove_table_vhost_entry(vhost_table.entry[i].entry_id);
            SWSS_LOG_NOTICE("[inserter] deleting cache entries, free entries:");
            if (status != SAI_STATUS_SUCCESS)
                SWSS_LOG_ERROR("[inserter] Failed at remove_table_vhost_entry %u, status: %u", i, status);
        }

    }


    if (init_status<1){
        status = sai_hostif_api->remove_hostif_table_entry(hostif_table_entryOid);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at remove_hostif_table_entry, rv %u", status);
    }

    if (init_status<2){
        status = sai_hostif_api->remove_hostif_trap(samplepackettrapOid);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at remove_hostif_trap, rv %u", status);
    }

    if (init_status<3){
        status = sai_hostif_api->remove_hostif_trap_group(trapGroupOid);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at remove_hostif_trap_group, rv %u", status);
    }

    if (init_status<4){
        status = sai_hostif_api->remove_hostif(hostifOid);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at remove_hostif, rv %u", status);
    }

    if (init_status<5){
        sai_attribute_t attr;
        attr.id = SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE;
        attr.value.oid = SAI_NULL_OBJECT_ID;
        status = sai_port_api->set_port_attribute(dpdk_port,&attr);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at samplepacket, rv %u", status);
    }   

    if (init_status<6){
        status = sai_samplepacket_api->remove_samplepacket(samplepacketOid);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at samplepacket, rv %u", status);
    }   

    SWSS_LOG_NOTICE("[inserter] sampler deinit success.");

    return 0;
}

sai_status_t bmt_cache_remove_rule(uint32_t offset){
    lock_guard<mutex> guard(vhost_table.free_offset_mutex);
    
    SWSS_LOG_NOTICE( "[evac] INFO: cache evacuator freeing vhost table offset %d",offset);
    sai_status_t status = gBmToRCacheOrch->RemoveTableVhost(vhost_table.entry[offset].entry_id);
    if (status == SAI_STATUS_SUCCESS) {
        vhost_table.entry[offset].valid = false;
        vhost_table.free_offsets.push_back(offset);
        g.cacheRemoveCount++;
        if (countersTable)
            countersTable->del(sai_serialize_object_id(vhost_table.entry[offset].entry_id));
    }
    return status;
}


typedef chrono::steady_clock::time_point bmt_time_t;
/* inserter main */
int bmt_cache_inserter(void)
{
    bmt_cache_debug_init();

    // int sockfd;
    // we wait untill swss finish init - (runing async)
    SWSS_LOG_ENTER();
	sleep(60);
    /* get dpdk port */
    SWSS_LOG_NOTICE("[inserter] DEBUG: initialization started.");
    dpdk_port = gBmToRCacheOrch->getDPDKPort();
    sai_status_t saistatus;
    SWSS_LOG_NOTICE("[inserter] DEBUG: found dpdk port (0x%lx).", dpdk_port);
    /* init dpdk port trapping via acl*/
    g.sampler_init_status = bmt_init_dpdk_traffic_sampler();
    SWSS_LOG_NOTICE("[inserter] DEBUG: sampler initialization finished. status: %d", g.sampler_init_status);
    if (g.sampler_init_status==0) { // only on init success
        pcap_t *handle;         /* Session handle */
        char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
        struct bpf_program fp;      /* The compiled filter expression */
        char filter_exp[] = "udp port 4789"; /* The filter expression */
        bpf_u_int32 mask;      /* The netmask of our sniffing device */
        bpf_u_int32 net;       /* The IP of our sniffing device */
        string dpdk_if = gBmToRCacheOrch->getDPDKPortIF();
        // struct pcap_pkthdr header;   /* The header that pcap gives us */
        // bmt_dpdk_pkt_t pkt;
        // sai_status_t status;
        // const u_char *packet;

        if (pcap_lookupnet(dpdk_if.c_str(), &net, &mask, errbuf) == -1) {
            SWSS_LOG_ERROR("Can't get netmask for device %s\n", dpdk_if.c_str());
            net = 0;
            mask = 0;
        }
        handle = pcap_open_live(dpdk_if.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            SWSS_LOG_ERROR("Couldn't open device %s: %s\n", dpdk_if.c_str(), errbuf);
            return(2);
        }
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            SWSS_LOG_ERROR("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            SWSS_LOG_ERROR("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        SWSS_LOG_NOTICE("Started listening on IF %s", gBmToRCacheOrch->getDPDKPortIF().c_str());
        // pcap_loop(handle, 0, bmt_parse_packet, NULL);
        bmt_time_t start;
        DpdkPacketMap pkt_map;
        pkt_map.clear();
        uint64_t window_time;
        uint32_t offset;
        while(g.scanDpdkPort) {
            pkt_map.clear();
            SWSS_LOG_NOTICE("[inserter] listening for %d packets...",  g.insertionWindowSize);
            start = std::chrono::steady_clock::now();
            pcap_loop(handle,  g.insertionWindowSize, bmt_parse_packet, (u_char *) &pkt_map);
            window_time = chrono::duration_cast<std::chrono::microseconds>(chrono::steady_clock::now() - start).count();
            if (g.pauseCacheInsertion) {
                continue;
            }
            for(auto const &it_pkt : pkt_map) {
                uint64_t bps = 1000000*it_pkt.second.second*PACKETS_PER_SAMPLE/window_time;
                if (bps > cacheManager.get_insertion_thresh()){
                    SWSS_LOG_NOTICE("[inserter] flow insertion, bytes/sec %lu times in the window",bps);
                  if (vhost_table.used_entries - vhost_table.free_offsets.size() >= (VHOST_TABLE_SIZE - CACHE_EVAC_SIZE)) { 
                        saistatus = cacheManager.consume_candidate(bps, offset);
                        if (saistatus != SAI_STATUS_SUCCESS) 
                            SWSS_LOG_ERROR("[inserter] ERROR: consume_candidate failed, bytes/sec %lu.",bps);
                    }
                    saistatus = bmt_cache_insert_vhost_entry(it_pkt.first.second, it_pkt.second.first, it_pkt.first.first);
                    SWSS_LOG_NOTICE("[inserter] [recv]    bmt_cache_insert_vhost_entry. status = %u",saistatus);
                    if (saistatus != SAI_STATUS_SUCCESS) 
                        SWSS_LOG_ERROR("[inserter] can't add entry to vhost table");
                    else
                        g.cacheInsertCount++;
                } else {
                    SWSS_LOG_NOTICE("[inserter] skipping flow insertion, bytes/sec %lu times in the window",bps);
                    g.cacheInsertSkip++;
                }
            }
        }
        pcap_close(handle);
    }
    /* deinit dpdk port trapping via acl*/
    SWSS_LOG_NOTICE("[inserter] DEBUG: dpdk listening done, deiniting:"); 
    int rc = bmt_deinit_dpdk_traffic_sampler(g.sampler_init_status);
    bmt_cache_debug_deinit();
    return(rc);

}


bmtCacheManager::bmtCacheManager(){
    lock_guard<mutex> guard(cacheMutex);
    evac_candidates.clear();
    evac_threshold = UINT64_MAX;
    insertion_threshold = 0;
}

void bmtCacheManager::print_candidates(){
    SWSS_LOG_ENTER();
    lock_guard<mutex> guard(cacheMutex);
    for (auto it=evac_candidates.begin(); it!=evac_candidates.end(); it++){
        SWSS_LOG_INFO("[print evac candidates] bps: %lu , offset: %d", it->first,it->second);
    }
}


/** added to candidate list the entry cosest to bps from below */
sai_status_t bmtCacheManager::consume_candidate(uint64_t bps,uint32_t &offset){
    lock_guard<mutex> guard(cacheMutex);    
    for (auto it=evac_candidates.begin(); it!=evac_candidates.end(); it++){
        cout << it->first<<endl;
        if(it->first < bps)
            continue;
        else
        {
            offset = (--it)->second; // removing previous element in list
            sai_status_t saistatus = bmt_cache_remove_rule(offset); // TODO move to consume rule
            if (saistatus != SAI_STATUS_SUCCESS) 
                SWSS_LOG_ERROR("[inserter] ERROR: cant remove rule, offset %d",offset);
                return saistatus;
            SWSS_LOG_NOTICE("candidate consumption sucess: bps: %lu ,offset: %d", it->first ,offset);
            evac_candidates.erase(it);
            return SAI_STATUS_SUCCESS;
        }
    }
    SWSS_LOG_NOTICE("No candidate fits requested bps %lu", bps);
    return SAI_STATUS_FAILURE; // list is empty;
}

void bmtCacheManager::insert_candidate(uint64_t bps,uint32_t offset){
    lock_guard<mutex> guard(cacheMutex);
    evac_candidates.push_back(make_pair(bps,offset));
    evac_candidates.sort();
    if (evac_candidates.size()>CACHE_EVAC_SIZE){
        evac_candidates.pop_back(); // remove candidate with highest bps
    }
}
uint64_t bmtCacheManager::get_insertion_thresh(){
    // todo mybe better to save the value of the last one consumed and not the current.
    if (evac_candidates.size()>0 && vhost_table.used_entries == (VHOST_TABLE_SIZE-1))
        return max((uint64_t) evac_candidates.back().first,(uint64_t) g.insertionThreshold); //lowest bps in candidates
    return g.insertionThreshold; // insert any if no candidates are avaliable
}
uint64_t bmtCacheManager::get_eviction_thresh(){
    if (evac_candidates.size() == CACHE_EVAC_SIZE)
        return evac_candidates.back().first;//highest bps in candidates
    return UINT64_MAX;
}

void bmt_flush_cache(){
    // TODO - protect from removal of non existing entry?
    // lock_guard<mutex> guard(vhost_table.free_offset_mutex);
    for (uint32_t i=0 ; i<vhost_table.used_entries ; i++){
        if (vhost_table.entry[i].valid) {
            bmt_cache_remove_rule(i);
        }
    }
    vhost_table.used_entries = 0;
    vhost_table.free_offsets.clear();
    g.flushCache = false;
    g.cacheInsertCount = 0;
    g.cacheInsertSkip = 0;
    g.cacheRemoveCount = 0;
}

void counter_read_by_offset(uint32_t offset, uint64_t *counter) {
  lock_guard<mutex> guard(counter_mutex);
  sai_bmtor_stat_t counter_id = SAI_BMTOR_STAT_TABLE_VHOST_HIT_OCTETS;
  *counter = 0;
  if (!vhost_table.entry[offset].valid) 
    return;
  //SWSS_LOG_NOTICE("reading vhost counter in offset %d", offset);
  sai_status_t status = sai_bmtor_api->get_bmtor_stats(vhost_table.entry[offset].entry_id, 1, &counter_id, counter);
  if (status)
    *counter = 0;

  vector<FieldValueTuple> fieldValues;
  fieldValues.emplace_back("VNI", to_string(vhost_table.entry[offset].vni));
  fieldValues.emplace_back("UNDERLAY_DIP", IpPrefix(htonl(vhost_table.entry[offset].underlay_dip), 32).to_string());
  fieldValues.emplace_back("OVERLAY_DIP", IpPrefix(htonl(vhost_table.entry[offset].overlay_dip), 32).to_string());
  fieldValues.emplace_back("BYTES", to_string(*counter));

  if (countersTable)
  	countersTable->set(sai_serialize_object_id(vhost_table.entry[offset].entry_id), fieldValues);
  //SWSS_LOG_NOTICE("write counters to DB key 0x%lx", vhost_table.entry[offset].entry_id);
}

void bmt_cache_evacuator(){
    SWSS_LOG_ENTER();
    uint64_t counter_values[EVAC_BATCH_SIZE];
    uint64_t counter_diff[EVAC_BATCH_SIZE];
    bmt_time_t stime[EVAC_BATCH_SIZE];
    uint32_t batch_start;
    uint32_t batch_end = 0;

    while (!g.exitFlag) {
        if (g.flushCache) {
            bmt_flush_cache();
        }
        batch_start = batch_end % VHOST_TABLE_SIZE; 
        batch_end = min(batch_start + EVAC_BATCH_SIZE, (uint32_t) VHOST_TABLE_SIZE);
        // seperate loops for constant read interval time.
        for (uint32_t i=batch_start ; i<batch_end; i++ ){
            counter_read_by_offset(i, &counter_values[i-batch_start]);
            stime[i-batch_start] = chrono::steady_clock::now();
        }
        usleep(100000);
        for (uint32_t i=batch_start ; i<batch_end; i++ ){
            counter_read_by_offset(i, &counter_diff[i-batch_start]);
            // counter normalized to bps:
            counter_diff[i-batch_start] = (counter_diff[i-batch_start] - counter_values[i-batch_start])*1000000/chrono::duration_cast<chrono::microseconds>(chrono::steady_clock::now() - stime[i-batch_start]).count();
        }
        for (uint32_t i=batch_start ; i<batch_end; i++ ){
            // SWSS_LOG_NOTICE("counter %d (bytes): 0x%lx", i, counter_diff[i-batch_start]);
            // TODO probably more efficiant to sort before iteration:
            if ((vhost_table.entry[i].valid) && (counter_diff[i-batch_start] < cacheManager.get_eviction_thresh())){ 
                cacheManager.insert_candidate(counter_diff[i-batch_start], i); 
                // SWSS_LOG_NOTICE("[evac] INFO: added evac candidate: offset: %d , counter delta: 0x%lx.",i,counter_diff[i-batch_start]);
            }
        }
        usleep(300000); // prevent busy wait
    }
}


void bmt_cache_counters_read() {
    while (!g.exitFlag) {
        {
            lock_guard<mutex> guard(vhost_table.free_offset_mutex);
            //SWSS_LOG_NOTICE("reading counters from all entries");
            for (uint32_t i=0; i<VHOST_TABLE_SIZE; i++) {
                counter_read_by_offset(i, &g.entryCounters[i]);
            }
        }
        usleep(100000);
    }
}

void bmt_cache_start() {
    countersDb = new DBConnector(COUNTERS_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);
    countersTable = new Table(countersDb, "BMTOR");
    thread t1_cache_inserter(bmt_cache_inserter);
    thread t2_cache_evacuator(bmt_cache_evacuator);
    thread t3_cache_counters_read(bmt_cache_counters_read);
    t1_cache_inserter.detach();
    t2_cache_evacuator.detach();
    t3_cache_counters_read.detach();
}
 
