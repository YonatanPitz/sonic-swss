
#ifndef __BMT_ORCH_CONSTANTS_H_
#define __BMT_ORCH_CONSTANTS_H_


/* Constants */
#define PACKETS_PER_SAMPLE 50 // ratio of dpdk packets to samples generated
#define VHOST_TABLE_SIZE 4 // Size allowed for dynamicly populated cache entries (not including local routes and dpdk default)
#define UNREFERENCED_PARAMETER(P)       (P)
#define BUF_SIZE		1024 // sampler buffer size
#define CONTROL_MTU 1100 //TODO
#define ETHER_TYPE	0x0800
#define TYPE_VLAN 0x8100
#define TYPE_IPV4 0x0800
#define CACHE_EVAC_SIZE (1) // the number of expected elements in vhost_table.free_offsets
#define EVAC_BATCH_SIZE (2) // number of counters to probe each time
#define EVAC_TRESH 2 // LEGACY can delete.
#define INSERTER_WINDOW_SIZE 20 //[usec]
#define INSERTER_THRESH 10000 // minimal bw of flow to enter cache
#endif /** __BMT_ORCH_CONSTANTS_H_ */
