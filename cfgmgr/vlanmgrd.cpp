#include <unistd.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <iostream>
#include <mutex>
#include <algorithm>
#include "dbconnector.h"
#include "select.h"
#include "exec.h"
#include "schema.h"
#include "macaddress.h"
#include "producerstatetable.h"
#include "vlanmgr.h"
#include "shellcmd.h"

using namespace std;
using namespace swss;

/* select() function timeout retry time, in millisecond */
#define SELECT_TIMEOUT 1000

/*
 * Following global variables are defined here for the purpose of
 * using existing Orch class which is to be refactored soon to
 * eliminate the direct exposure of the global variables.
 *
 * Once Orch class refactoring is done, these global variables
 * should be removed from here.
 */
global_config_t g;

int main(int argc, char **argv)
{
    Logger::linkToDbNative("vlanmgrd");
    SWSS_LOG_ENTER();

    SWSS_LOG_NOTICE("--- Starting vlanmgrd ---");

    try
    {
        vector<string> cfg_vlan_tables = {
            CFG_VLAN_TABLE_NAME,
            CFG_VLAN_MEMBER_TABLE_NAME,
        };

        DBConnector cfgDb(CONFIG_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);
        DBConnector appDb(APPL_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);
        DBConnector stateDb(STATE_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);

        /*
         * swss service starts after interfaces-config.service which will have
         * switch_mac set.
         * Dynamic switch_mac update is not supported for now.
         */
        Table table(&cfgDb, "DEVICE_METADATA", CONFIGDB_TABLE_NAME_SEPARATOR);
        std::vector<FieldValueTuple> ovalues;
        table.get("localhost", ovalues);
        auto it = std::find_if( ovalues.begin(), ovalues.end(), [](const FieldValueTuple& t){ return t.first == "mac";} );
        if ( it == ovalues.end() ) {
            throw runtime_error("couldn't find MAC address of the device from config DB");
        }
        g.macAddress = MacAddress(it->second);

        VlanMgr vlanmgr(&cfgDb, &appDb, &stateDb, cfg_vlan_tables);

        std::vector<Orch *> cfgOrchList = {&vlanmgr};

        swss::Select s;
        for (Orch *o : cfgOrchList)
        {
            s.addSelectables(o->getSelectables());
        }

        SWSS_LOG_NOTICE("starting main loop");
        while (true)
        {
            Selectable *sel;
            int fd, ret;

            ret = s.select(&sel, &fd, SELECT_TIMEOUT);
            if (ret == Select::ERROR)
            {
                SWSS_LOG_NOTICE("Error: %s!", strerror(errno));
                continue;
            }
            if (ret == Select::TIMEOUT)
            {
                vlanmgr.doTask();
                continue;
            }

            auto *c = (Executor *)sel;
            c->execute();
        }
    }
    catch(const std::exception &e)
    {
        SWSS_LOG_ERROR("Runtime error: %s", e.what());
    }
    return -1;
}
