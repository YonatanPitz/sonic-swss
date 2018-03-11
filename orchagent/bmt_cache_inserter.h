#ifndef  __BMT_CACHE_INSERTER_H_
#define __BMT_CACHE_INSERTER_H_

extern "C" {
#include "saistatus.h"
}

#include "bmt_orch_constants.h"
#include <mutex>
#include <list>
#include <iostream>


using namespace std;
void bmt_cache_start();

#endif /** __BMT_CACHE_INSERTER_H_ */

typedef pair<uint64_t,uint32_t>bmt_rule_evac_candidate_t; // bps,offset
class bmtCacheManager{
    private: 
        mutex cacheMutex;
        list<bmt_rule_evac_candidate_t> evac_candidates;
        uint64_t evac_threshold;
        uint64_t insertion_threshold;
    public:
        bmtCacheManager();
        void insert_candidate(uint64_t bps,uint32_t offset);
        sai_status_t consume_candidate(uint64_t bps, uint32_t &offset);
        //bmt_rule_evac_candidate_t free_candidate();
        uint64_t get_insertion_thresh();
        uint64_t get_eviction_thresh();
        void print_candidates();
};
