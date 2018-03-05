#ifndef __BMT_COMMON_H_
#define __BMT_COMMON_H_

extern "C" {
#include "sai.h"
#include "saistatus.h"
}
 
#include <sairedis.h>


typedef struct bmt_init_status_t{
  bool tunnel_encap_map_created = false;
  bool tunnel_decap_map_created = false;
  bool tunnel_decap_map_entry_created = false;
  bool tunnel_encap_map_entry_created = false;
  bool tunnel_created = false;
  bool tunnel_term_table_entry_created = false;
  bool vhost_table_entry_created = false;
  bool default_vhost_table_entry_created = false;
  bool peering_entry_created = false;
  bool sai_ext_api_inited = false;
  bool vlan_created = false;
  bool vlan_member_created = false;
  bool dpdk_vlan_member_created = false;
  bool bridge_created = false;
  bool bridge_port_created = false;
  bool dpdk_bridge_port_created = false;
} bmt_init_status_t;


/*extern sai_switch_api_t *switch_api;
extern sai_object_id_t g_switch_id;
extern sai_port_api_t *port_api;
extern sai_tunnel_api_t *tunnel_api;
extern sai_vlan_api_t *vlan_api;
extern sai_bridge_api_t *bridge_api;
extern sai_bmtor_api_t *bmtor_api;
extern sai_object_id_t tunnel_encap_map;
extern sai_object_id_t tunnel_decap_map;
extern sai_object_id_t tunnel_decap_map_entry;
extern sai_object_id_t tunnel_encap_map_entry;
extern sai_object_id_t tunnel_id;
extern sai_object_id_t tunnel_term_table_entry;
extern sai_object_id_t bridge_id;
extern sai_object_id_t vlan_oid;
extern sai_object_id_t vlan_member_oid;
extern sai_object_id_t dpdk_vlan_member_oid;
extern sai_object_id_t bridge_port_id;
extern sai_object_id_t dpdk_bridge_port_id;
extern sai_object_id_t vhost_table_entry;
extern sai_object_id_t default_vhost_table_entry;
extern sai_object_id_t peering_entry;
extern sai_object_id_t ports_to_bind[32];
extern sai_object_list_t ports_to_bind_list;
*/

sai_object_id_t sai_get_port_id_by_front_port(uint32_t hw_port);
void  bmt_deinit(bmt_init_status_t* bmt_common_init);
int   bmt_init(bmt_init_status_t* bmt_common_init);
void  bmt_cache_start();

#endif /* __BMT_COMMON_H_ */