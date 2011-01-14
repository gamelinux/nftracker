#include "config.h"
#include "util-stats.h"
#include "util-system-end.h"
#include "util-session.h"
#include "util-search.h"

extern globalconfig config;

void set_end_sessions()
{
    //intr_flag = 3;

    if (ISSET_CONFIG_INPACKET(config) == 0) {
        config.tstamp = time(NULL);
        end_sessions();
//        update_file_list();
//        intr_flag = 0;
        alarm(CHECK_TIMEOUT);
    }
}

void gameover()
{
    if (ISSET_CONFIG_INPACKET(config) == 0) {
//        clear_file_list();
        end_all_sessions();
        free_queue();
//        del_signature_lists();
//        unload_file_sigs();
//        end_logging();
        print_stats();
        print_pcap_stats();
        if (config.handle != NULL) pcap_close(config.handle);
//        free_config(); // segfault here !
        if (config.sig_file != NULL) del_all_sigs_file ();
        free_config();
        printf("\nnftracker ended\n");
        exit(0);
    }
    SET_CONFIG_INTR(config);
}

