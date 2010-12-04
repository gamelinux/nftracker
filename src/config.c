/*
**
** Copyright (C) 2010, Edward Fjellskål <edwardfjellskaal@gmail.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

/*  I N C L U D E S  *********************************************************/
#include "common.h"
#include "nftracker.h"
#include "util-system.h"
#include "config.h"

/*  G L O B A L E S  *********************************************************/
extern globalconfig config;

/* F U N C T I O N S  ********************************************************/

void set_default_config_options()
{
//    config.ctf    |= CO_SYN;
//    config.ctf    |= CO_RST;
//    config.ctf    |= CO_FIN;
//    config.ctf    |= CO_ACK;
 //   config.ctf    |= CO_SYNACK;
    //config.ctf    |= CO_ICMP;
    //config.ctf    |= CO_UDP;
    //config.ctf    |= CO_OTHER;
    config.cof    |= CS_TCP_SERVER;
    config.cof    |= CS_TCP_CLIENT;
    config.cof    |= CS_UDP_SERVICES;
    config.dev     = strdup("eth0");
    config.bpff    = strdup("");
//    config.dpath   = "/tmp";
    config.pidfile = strdup("prads.pid");
    config.pidpath = strdup("/var/run");
//    config.assetlog= bfromcstr(LOGDIR PRADS_ASSETLOG);
    // default source net owns everything
    config.s_net   = "0.0.0.0/0,::/0";
    config.errbuf[0] = '\0';
//    config.configpath = CONFDIR "";
    // files should be relative to configpath somehow
//    config.sig_file_syn = CONFDIR "tcp-syn.fp";
//    config.sig_file_synack = CONFDIR "tcp-synack.fp";
//    config.sig_file_ack = CONFDIR "tcp-stray-ack.fp";
//    config.sig_file_fin = CONFDIR "tcp-fin.fp";
//    config.sig_file_rst = CONFDIR "tcp-rst.fp";
//    config.sig_syn = NULL;
//    config.sig_synack = NULL;
//    config.sig_ack = NULL;
//    config.sig_fin = NULL;
//    config.sig_rst = NULL;
//    config.sig_hashsize = 241;
    // don't chroot by default
    config.chroot_dir = NULL;
}

