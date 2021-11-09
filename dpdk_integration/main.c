/*
  This file is a part of Qosmos ixEngine.

   Copyright  Qosmos 2014 - 2016 All rights reserved

  This computer program and all its components are protected by
  authors' rights and copyright law and by international treaties.
  Any representation, reproduction, distribution or modification
  of this program or any portion of it is forbidden without
  Qosmos explicit and written agreement and may result in severe
  civil and criminal penalties, and will be prosecuted
  to the maximum extent possible under the law.
*/

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* DPDK headers */
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_pci.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_version.h>
#include <rte_jhash.h>

#include "customize.h"
#include "ndpi_api.h"

#define MBUFSZ (2048  + RTE_PKTMBUF_HEADROOM)
/**
 * Set the number of queue descriptor for lcores' software ring queue
 */
#define LCORE_QUEUESZ 1024 * 32

/**
 * Set number of queue descriptor for port's Hardware receive ring queue
 * 3000 is max number of packet in HW queue
 */
#define RXDNB 256
#define TXDNB 512
#define PKTBURSTNB 32
#define NB_QUEUE 3

#define QNAMEPREFIX "LCOREQ"

/**
 * Safe for 10^20 lcores
 */
#define QNAMESZ (sizeof(QNAMEPREFIX) + 20)

#if RTE_VERSION > RTE_VERSION_NUM(19, 11, 0, 0)

static struct rte_eth_conf ethconf = {
    .rxmode = {
        .split_hdr_size = 0,    /**< Header Split buffer size */
        .max_rx_pkt_len = 9600, /**< MTU to the max */
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};
#else
static struct rte_eth_conf ethconf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .header_split   = 0,/**< Header Split disabled. */ /* 1 disable rx_vec_allowed */
        .hw_ip_checksum = 0,/*modify it to 0 for performance. */
        .hw_vlan_filter = 0,/**< VLAN filtering enabled. */
        .hw_vlan_strip  = 0,/**< VLAN strip enabled. */
        .hw_vlan_extend = 0,/**< Extended VLAN disabled. */
        .jumbo_frame    = 0,/**< Jumbo Frame Support disabled. */
        .hw_strip_crc   = 1,/**< CRC stripping by hardware enabled. */
        .enable_scatter = 0,
        .enable_lro     = 0,
        .ignore_offload_bitfield = 0
	},
	.rx_adv_conf = {
		.rss_conf = {
            .rss_key = NULL,
			.rss_hf = ETH_RSS_TCP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

#endif
/* Timestamp */
static uint64_t starting_cycles;
static uint64_t hz;
static struct timeval  start_time;

/* Timer for stats */
static int64_t timer_period = 3;      /* default period is 3 seconds */
static uint64_t timer_cycles;
// used memory counters
u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
u_int8_t human_readeable_string_len = 5;
/* 8 is enough for most protocols, Signal and SnapchatCall require more */
u_int8_t max_num_udp_dissected_pkts = 24;
/* due to telnet */
u_int8_t max_num_tcp_dissected_pkts = 80;
int nDPI_LogLevel = 0;
char *_debug_protocols = NULL;

u_int8_t enable_protocol_guess = 1, enable_payload_analyzer = 0, enable_joy_stats = 0;

/**
 * Structure describing a lcore for packet processing
 */
static uint64_t dispatch_pkts_rx =
    0;        /* number of pktx rx on dispatch thread */
struct lcore {
    struct rte_ring *queue;                  /* lcore_queue */
    uint64_t ring_drop;                      /* #pkts drop on ring */
    uint64_t ring_enqueued;                  /* #pkts drop on ring */
    uint64_t worker_pkts_rx;                 /* #pkts received on worker */
    uint64_t worker_pkts_processed;          /* #pkts processed by worker */
    uint64_t worker_pkts_errors;             /* #pkts erronoeous on dpi */

    uint64_t worker_flows_expired;           /* #flow expired */
    uint64_t worker_bytes_processed;         /* #bytes processed */
    uint64_t worker_dispatch_pkts_rx;        /* #pkts dispatch on worker */
    unsigned int id;                         /* worker_id */
    uint16_t cpu_id;                         /* cpu logic_id */
};

/**
 * Temporary packet per thread cache in order to use more efficient
 * rte_ring_sp_enqueue_bulk
 */
struct mbuf_queue {
    struct rte_mbuf *pkt[PKTBURSTNB];
    unsigned int size;
};


static struct rte_mempool *pktmbuf_pool = NULL;
static unsigned long hwsize = RXDNB;
static unsigned long swsize = LCORE_QUEUESZ;
static uint16_t port_nb = 0;
struct lcore * g_lcore = NULL;
static uint16_t nb_queue = 0;
static uint16_t dpi_workers = 0;
#define RECIVE_WORKER 2
static uint16_t g_worker = RECIVE_WORKER;
static int g_hash_method = 0;

static int noprint = 0;
static int monitoring = 0;
static int nb_flows_arg;

static volatile char di_stop = 0;

struct di_reader_thread {
  struct ndpi_workflow *workflow;
  pthread_t pthread;
  u_int64_t last_idle_scan_time;
  u_int32_t idle_scan_idx;
  u_int32_t num_idle_flows;
  struct ndpi_flow_info *idle_flows[1024];
};

struct ipv4_5tuple_t {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t  src_port;
    uint16_t dst_port;
    uint8_t  proto;
};

static struct di_reader_thread ndpi_thread_info[16];

static inline void usage(char const *p)
{
    fprintf(stderr, "Usage:\n%s <dpdk_cmdline> -- [options]\n"
            "Options:\n"
            "\t--nic_ring_size: Size of hardware queue\n"
            "\t--dpi_ring_size: Size of software queue\n"
            "\t--enable-monitoring: Enable performance monitoring. Resulting statistics (in terms of memory and processing time) are displayed at exit.\n"
            "\t--no-print: Do not print classification\n"
            "\t--timer: time between stats printing (s)\n"
            "\t--nb_flows: maximal number of flow context per worker\n"
            "\t--receiver: number of dispatch worker,default 2\n"
            "\t--hash: [0|1|2] default:0(0 <-->5tuple;1 <-->2tuple;2 <--> dpdk-rss)\n",
            p);
}

/**
 * Stop application when SIGINT is received
 */
void di_sig_stop(int s)
{
    (void)s;
    di_stop = 1;
}

uint32_t hash_5tuple(struct ipv4_5tuple_t *key, uint32_t seed)
{
    uint32_t hash_val;
    hash_val = rte_jhash_2words(key->src_addr, key->dst_addr, seed);
    hash_val = rte_jhash_2words((uint32_t)key->src_port, (uint32_t)key->dst_port, hash_val);
    hash_val = rte_jhash_2words(seed, hash_val, (uint32_t)key->proto);
    return hash_val;
}

uint32_t hash_2tuple(struct ipv4_5tuple_t *key, uint32_t seed)
{
    uint32_t hash_val;
    hash_val = rte_jhash_2words(key->src_addr, key->dst_addr, seed);
    return hash_val;
}


__rte_unused uint32_t di_packet_ntuple_hashkey_get(unsigned char *buffer, int is_5tuple)
{
    struct ipv4_5tuple_t key;
    struct ethhdr *eth = (struct ethhdr *)buffer;
    if (eth == NULL) {
        fprintf(stderr, "%s[%d]\n", __func__,__LINE__);
        return 0;
    }
    if(eth->h_proto != htons(0x0800))
        return 0;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    key.src_addr = iph->saddr;
    key.dst_addr = iph->daddr;
    u_int16_t iphdrlen = (iph->ihl << 2) + sizeof(struct ethhdr);
    if (iph->protocol == 6) {
        struct tcphdr *tcp = (struct tcphdr *)(buffer + iphdrlen);
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    }
    else if (iph->protocol == 17) {
        struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen);
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    }
    else {
         key.src_port = 0;
         key.dst_port = 0;
    }
    key.proto = iph->protocol;
    if (is_5tuple)
        return hash_5tuple(&key, 0xdeadbeef);
    else
        return hash_2tuple(&key, 0xdeadbeef);
}


/**
 * Helper functions
 */
static inline unsigned long int
hash_compute(struct rte_mbuf *mbuf, __rte_unused unsigned int len)
{
    uint32_t hashkey = 0;
    static int count = 1000;
    unsigned char * buffer = rte_pktmbuf_mtod(mbuf, unsigned char *);
    switch (g_hash_method) {
#ifdef QOS_MOS
        case 0:
            {
                int ret = QMDPI_EINVAL;
                ret= qmdpi_packet_ntuple_hashkey_get((const char *)buffer, len, 
                      QMDPI_PROTO_ETH, QMDPI_5TUPLE_HASHKEY, &hashkey);
                if (ret == QMDPI_EINVAL) {
                    hashkey = 0;
                }
            }
            break;
        case 1:
            {
                hashkey = qmdpi_packet_hashkey_get((const char *)buffer, len, QMDPI_PROTO_ETH);
            }
            break;
#endif
        case 2:
            {
                if (unlikely(!(mbuf->ol_flags & PKT_RX_RSS_HASH))) {
                    char buf[256];
                    rte_get_rx_ol_flag_list(mbuf->ol_flags, buf, sizeof(buf));
                    if (count > 0)
                        fprintf(stderr, " %d flags 0x%lx %s\n", rte_lcore_id(), mbuf->ol_flags, buf);
                    mbuf->ol_flags |= PKT_RX_RSS_HASH;
                    mbuf->hash.rss = 0;
                }
                hashkey = mbuf->hash.rss;
                if (count > 0) {
                    fprintf(stderr, " %d %u hash_compute\n", rte_lcore_id(), hashkey);
                    count--;
                }
            }
            break;
        case 3:
            {
                static uint32_t rr = 0;
                rr++;
                hashkey = rr;
            }
            break;
        case 4:
            {
                hashkey = di_packet_ntuple_hashkey_get(buffer, 1);
            }
            break;
        case 5:
            {
                hashkey = di_packet_ntuple_hashkey_get(buffer, 0);
            }
            break;
        default:
            break;
    }
    return hashkey;
}

static inline
void calculate_timestamp(struct timeval *ts)
{
    uint64_t       cycles;
    struct timeval cur_time;

    cycles = rte_get_timer_cycles() - starting_cycles;
    cur_time.tv_sec = cycles / hz;
    cur_time.tv_usec = ((cycles % hz) * 1000000) / hz;

    timeradd(&start_time, &cur_time, ts);

    if (unlikely(cur_time.tv_sec > 5 * 60)) {
        /* Correct time every 5 min. */
        starting_cycles = rte_get_timer_cycles();
        gettimeofday(&start_time, NULL);

#ifdef DPDK_CLOCK_DEBUG
        /*
        ** show drift from real time.
        */
        LOG(stderr, "calibrating clocks...\n");

        LOG(stderr,
            "our time <%10ld.%06ld>\n"
            "current  <%10ld.%06ld> \n"
            "diff     <%10ld.%06ld> \n",
            (long int)ts->tv_sec, (long int)ts->tv_usec,
            (long int)start_time.tv_sec, (long int) start_time.tv_usec,
            (long int)start_time.tv_sec - (long int) ts->tv_sec,
            (long int)start_time.tv_usec - (long int) ts->tv_usec);
#endif /* DPDK_CLOCK_DEBUG */
    }
}

/**
 * Print dpdk queue statistics
 */
static void
di_stats_print(struct lcore const *lcore, unsigned int lcorenb,
               uint16_t portnb)
{
    struct rte_eth_stats st;
    unsigned int lc;
    uint16_t p;
    uint64_t total_pkts_processed = 0;
    uint64_t total_bytes_processed = 0;
    static uint64_t old_pkts_processed = 0;
    static uint64_t old_bytes_processed = 0;
    uint64_t total_flows_expired = 0;
    static uint64_t old_pkts = 0;
    static uint64_t old_errors = 0;
    static uint64_t old_missed = 0;
    static uint64_t old_enqueued= 0;
    static uint64_t old_drop = 0;

    const char clr[] = { 27, '[', '2', 'J', '\0' };
    const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };


    fprintf(stderr, "%s%s", clr, topLeft);
    fprintf(stderr, "\nStatistics ======================================\n\n");
    
    for (lc = 0; lc < g_worker; ++lc) {
        dispatch_pkts_rx += lcore[lc].worker_dispatch_pkts_rx;
    }
    fprintf(stderr, "NIC; (total pkts rx: %lu) \n", dispatch_pkts_rx);

    for (p = 0; p < portnb; ++p) {
        rte_eth_stats_get(p, &st);
        fprintf(stderr,
                " Port #%u: %lu received / %lu errors / %lu missed\n",
                p, st.ipackets, st.ierrors,
                st.imissed);
        long double nic_pkt_rate = (st.ipackets - old_pkts) / timer_period;
        long double nic_err_rate = (st.ierrors - old_errors) /timer_period;
        long double nic_mis_rate = (st.imissed - old_missed) /timer_period;
        fprintf(stderr,
                "%10"PRIu64" pps / %"PRIu64" pps / %"PRIu64" pps\n",
                 (uint64_t)nic_pkt_rate, (uint64_t)nic_err_rate, (uint64_t)nic_mis_rate);
    }

    fprintf(stderr, "\nReceive Software Ring\n");

    for (lc = 0; lc < g_worker; ++lc) {
        if(lc == 0) {
            long double ring_eq_rate = (lcore[lc].ring_enqueued - old_enqueued) / timer_period;
            long double ring_drop_rate = (lcore[lc].ring_drop - old_drop) /timer_period;
            fprintf(stderr, " Core #%u: %lu enqueued / %lu dropped /"
                "%2"PRIu64" eqpps / %"PRIu64" drpps\n",
                lcore[lc].id,
                lcore[lc].ring_enqueued, lcore[lc].ring_drop,
                (uint64_t)ring_eq_rate,(uint64_t)ring_drop_rate);
        }
        else
            fprintf(stderr, " Core #%u: %lu enqueued / %lu dropped \n",
                lcore[lc].id,
                lcore[lc].ring_enqueued, lcore[lc].ring_drop);
    }

    fprintf(stderr, "\nDPI :\n");

    for (lc = g_worker; lc < lcorenb; ++lc) {
        fprintf(stderr,
                " Core #%u: %lu rx / %lu processed / %lu err  \n",
                lcore[lc].id,
                lcore[lc].worker_pkts_rx,
                lcore[lc].worker_pkts_processed,
                lcore[lc].worker_pkts_errors
               );
        total_pkts_processed += lcore[lc].worker_pkts_processed;
        total_bytes_processed += lcore[lc].worker_bytes_processed;
    }
    fprintf(stderr, "\n");

    for (lc = g_worker; lc < lcorenb; ++lc) {
        fprintf(stderr,
                " Core #%u: %lu flows expired\n",
                lcore[lc].id,
                lcore[lc].worker_flows_expired);
        total_flows_expired += lcore[lc].worker_flows_expired;
    }
    fprintf(stderr, "\n");

    long double pkt_rate = (total_pkts_processed - old_pkts_processed) /
                           timer_period;
    long double byte_rate = (total_bytes_processed - old_bytes_processed) /
                            timer_period;

    fprintf(stderr,
            "\nAggregate statistics :\n"
            "\nTotal pkts processed: %18"PRIu64
            "\nTotal pps : %28"PRIu64
            "\npps/core : %29"PRIu64
            "\nTotal rate (Mbps) : %20"PRIu64
            "\nrate (Mbps) /core : %20"PRIu64
            "\nTotal flows expired: %19"PRIu64,
            total_pkts_processed,
            (uint64_t)pkt_rate,
            (uint64_t)pkt_rate / (dpi_workers),
            ((uint64_t)byte_rate << 3) / (1000000),
            ((uint64_t)byte_rate << 3) / (1000000*(rte_lcore_count() - 1)),
            total_flows_expired);

    fprintf(stderr,
            "\n====================================================\n");

    old_pkts_processed = total_pkts_processed;
    old_bytes_processed = total_bytes_processed;
    old_pkts = st.ipackets;
    old_errors = st.ierrors;
    old_missed = st.imissed;
    old_enqueued = lcore[0].ring_enqueued;
    old_drop = lcore[0].ring_drop;
}

static int di_master_loop(struct lcore *lc, uint16_t portnb)
{
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    uint16_t cid = rte_lcore_id();
    unsigned int slavenb;
    prev_tsc = 0;
    timer_tsc = 0;
    slavenb = rte_lcore_count() - 1;

    fprintf(stderr, "cid %d %d start\n",cid, rte_lcore_id());

    while (!di_stop) {
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;

        if (timer_cycles > 0) {   /* timer enabled */
            timer_tsc += diff_tsc;
            if (unlikely(timer_tsc >= timer_cycles)) { /* timeout */
                di_stats_print(lc, slavenb, portnb);
                timer_tsc = 0;
            }
        }
        prev_tsc = cur_tsc;
    }

    return 0;
}

/**
 * Get packet and dispatch them to each lcore
 */
static int di_pkt_dispatch(struct lcore *lc, uint16_t cid)
{
    struct rte_mbuf *pkt[PKTBURSTNB];
    struct timeval *ts = NULL;
    unsigned int ret;
    uint16_t nbrx;
    uint16_t p;
    uint16_t i;
    uint16_t qid = lc->id;

    for (p = 0; p < port_nb; p++) {
        if (rte_eth_dev_socket_id(p) > 0 &&
                rte_eth_dev_socket_id(p) !=
                (int)rte_socket_id()) {
            fprintf(stderr, "WARNING, port %u is on remote NUMA node to "
                    "polling thread.\n\tPerformance will "
                    "not be optimal.\n", p);
        }
    }
    fprintf(stderr, "cid %d %d qid %d di_pkt_dispatch \n",cid, rte_lcore_id(), qid);
    while (!di_stop) {
        for (p = 0; p < port_nb; ++p) {
            nbrx = rte_eth_rx_burst(p, qid, pkt, PKTBURSTNB);
            if (unlikely(nbrx == 0)) {
                continue;
            }

            for (i = 0; i < nbrx; i++) {
                //dispatch_pkts_rx++;
                lc->worker_dispatch_pkts_rx++;
                /* Software hash for dispatching */
                unsigned long int hash = hash_compute(pkt[i],
                                                      rte_pktmbuf_data_len(pkt[i]));
                int soft_queue = hash % dpi_workers;
                if (soft_queue > dpi_workers)
                    soft_queue = 0;
                soft_queue += g_worker;
                if (g_lcore[soft_queue].queue == NULL) {
                    fprintf(stderr,"%s[%d] qeueue %d hash %ld %d\n",__func__,__LINE__,
                        soft_queue, hash, dpi_workers);
                    rte_pktmbuf_free(pkt[i]);
                    continue;
                }
                ts = (struct timeval *) rte_pktmbuf_prepend(pkt[i],
                                                            (uint16_t) sizeof(struct timeval));
                calculate_timestamp(ts);

                ret = rte_ring_enqueue_bulk(g_lcore[soft_queue].queue, (void *const *)&pkt[i], 1,
                                            NULL);
                if (unlikely(ret == 0)) {
                    rte_pktmbuf_free(pkt[i]);
                    lc->ring_drop += 1;
                } else {
                    lc->ring_enqueued += 1;
                    
                }
            }
            }
    }

    return 0;
}

static void di_result_display(u_int16_t thread_id, struct ndpi_proto *p)
{
    if (!noprint)
        fprintf(stdout, "thredid #%u\t\tClassification protol: %u %u\n", thread_id, 
            p->master_protocol, p->app_protocol);
    return;
}

static int di_ndpi_process_packet(u_char *args, const struct pcap_pkthdr *header, 
            const u_char *packet)
{
    //return 0;
    ndpi_risk flow_risk;
    u_int16_t thread_id = *((u_int16_t*)args);
    int ret = 0;
    #if 0
     /* allocate an exact size buffer to check overflows */
    uint8_t *packet_checked = ndpi_malloc(header->caplen);
    if(packet_checked == NULL){
        return -1;
    }
    memcpy(packet_checked, packet, header->caplen);
    struct ndpi_proto p = ndpi_workflow_process_packet(ndpi_thread_info[thread_id].workflow, header, 
                        packet_checked, &flow_risk, NULL);
    #endif
    struct ndpi_proto p = ndpi_workflow_process_packet(ndpi_thread_info[thread_id].workflow, header, 
                        packet, &flow_risk, NULL);
    if (p.master_protocol == NDPI_PROTOCOL_UNKNOWN 
        && p.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
        ret = -1;
    }

    di_result_display(thread_id, &p);
    #if 0
    /* check for buffer changes */
    if(memcmp(packet, packet_checked, header->caplen) != 0)
        printf("INTERNAL ERROR: ingress packet was modified by nDPI: this should not happen "
        "[thread_id=%u, packetId=%lu, caplen=%u]\n", thread_id, 
        (unsigned long)ndpi_thread_info[thread_id].workflow->stats.raw_packet_count, 
        header->caplen);
    #endif
    /*
    Leave the free as last statement to avoid crashes when ndpi_detection_giveup()
    is called above by printResults()
    */
    #if 0
    if (packet_checked) {
        ndpi_free(packet_checked);
        packet_checked = NULL;
    }
    #endif
    return ret;
}

/**
 * Send packet to ixe
 */
static int di_ndpi_loop(struct lcore *lc, uint16_t cid)
{
    struct rte_mbuf *mbuf[PKTBURSTNB];
    unsigned int nb, i;
    unsigned int thread_id = (lc->id - g_worker);
    int ret = 0;

    fprintf(stderr, "cid %d %d is di_pkt_loop\n",cid, rte_lcore_id());
    if(!lc->queue)
        fprintf(stderr,"%s[%d] \n",__func__,__LINE__);
    while (!di_stop) {
        nb = rte_ring_dequeue_burst(lc->queue,
                                    (void **)mbuf,
                                    PKTBURSTNB,
                                    NULL);
        if (unlikely(nb == 0)) {
            continue;
        }

        lc->worker_pkts_rx += nb;

        for (i = 0; i < nb; ++i) {
            if (rte_pktmbuf_data_len(mbuf[i]) == 0) {
                rte_pktmbuf_free(mbuf[i]);
                continue;
            }

            struct timeval ts;
            memcpy(&ts, rte_pktmbuf_mtod(mbuf[i], char *), sizeof(struct timeval));
            struct pcap_pkthdr h;
            rte_pktmbuf_adj(mbuf[i], (uint16_t) sizeof(struct timeval));
            int len = rte_pktmbuf_data_len(mbuf[i]);
            h.len = h.caplen = len;
            h.ts = ts;
            ret = di_ndpi_process_packet((u_char*)&thread_id, &h,
                (const u_char *)rte_pktmbuf_mtod(mbuf[i], char *));
            
            if (unlikely(ret < 0)) {
                ++lc->worker_pkts_errors;
            } else {
                lc->worker_bytes_processed += (len+20);
                lc->worker_pkts_processed++;
            }
            rte_pktmbuf_free(mbuf[i]);
        }
    }


    return 0;
}

/**
 * Send packet to ixe
 */
static int di_pkt_loop(void *arg) 
{
    int ret = 0;
    struct lcore *lc = (struct lcore *)arg;
    uint16_t cid = lc->cpu_id;
    if (cid > g_worker) {
        ret = di_ndpi_loop(lc, cid);
    }
    else
        ret = di_pkt_dispatch(lc, cid);
    return ret;
}

/**
 * Initialize dpdk application.
 * Should be called on master lcore as dpdk application initialization functions
 * are not thread safe
 */
static int di_app_init(int argc, char **argv)
{
    int ret = 0;
    struct sigaction sighdl = {
        .sa_handler = di_sig_stop,
        .sa_flags = 0
    };
    sigemptyset(&sighdl.sa_mask);

    /**
     * Initialize Environment Abstraction Layer
     * This manages hardware resources (memory, PCI devices, timers, ...) and
     * threads.
     */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "EAL initialization fail\n");
        goto out;
    }

    if (rte_lcore_count() <= 1) {
        ret = -1;
        fprintf(stderr,
                "Number of cores should be > 1 (please check your DPDK command line arguments)\n");
        goto out;
    }

    nb_queue = g_worker;
    dpi_workers = rte_lcore_count() - g_worker -1;
    if (dpi_workers == 0) {
        ret = -1;
        fprintf(stderr,
                "Dispatch worker master be > 1 (please check your DPDK command line arguments)\n");
        goto out;
    }

    /**
     * Create the mbuf pool:
     */
    pktmbuf_pool = rte_mempool_create("mbuf_pool",
                                      hwsize + swsize * (g_worker), MBUFSZ, 256,
                                      sizeof(struct rte_pktmbuf_pool_private),
                                      rte_pktmbuf_pool_init, NULL,
                                      rte_pktmbuf_init, NULL, SOCKET_ID_ANY, 0);

    if (pktmbuf_pool == NULL) {
        ret = -ENOMEM;
        fprintf(stderr, "Mempool creation fail : %d (%s)\n", rte_errno,
                rte_strerror(rte_errno));
        goto out;
    }

    /**
     * Install signal handler on SIGINT to stop the application
     */
    ret = sigaction(SIGINT, &sighdl, NULL);

out:
    return ret;
}

/**
 * Exit dpdk application.
 */
static int di_app_exit(void)
{
#if RTE_VERSION > RTE_VERSION_NUM(19, 11, 0, 0)
    return rte_eal_cleanup();
#else
    return 1;
#endif
}

/**
 * Configure an ethernet port
 */
static int di_ethport_init(int16_t port)
{
    int ret;
    int qid;
     /* setting the rss key */
    __rte_unused static const uint8_t key[] = {
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    };
    
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    /**
     * The ethernet device is configured to have nb_queue receive queue and no
     * transmit queue
     */
    memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port, &dev_info);
    memcpy(&txconf, &dev_info.default_txconf, sizeof(struct rte_eth_txconf));
    ethconf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)&key;
    ethconf.rx_adv_conf.rss_conf.rss_key_len = sizeof(key);
    ethconf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP|ETH_RSS_TCP|ETH_RSS_UDP;
    ethconf.rxmode.offloads = dev_info.rx_offload_capa;
    ret = rte_eth_dev_configure(port, nb_queue, nb_queue, &ethconf);
    if (ret < 0) {
        fprintf(stderr, "Ethernet configuration fail\n");
        goto out;
    }


    for (qid = 0; qid < nb_queue; qid++) {
        /**
         * Then allocate and set up the receive queues for this Ethernet device
         */
        ret = rte_eth_rx_queue_setup(port, qid, hwsize, SOCKET_ID_ANY, NULL,
                                     pktmbuf_pool);
        if (ret < 0) {
            fprintf(stderr, "Ethernet rx queue setup fail\n");
            goto out;
        }

        /**
         * Then allocate and set up the transmit queue for this Ethernet device
         * This is needed by dpdk even if not used
         */
        ret = rte_eth_tx_queue_setup(port, qid, TXDNB, SOCKET_ID_ANY, &txconf);
        if (ret < 0) {
            fprintf(stderr, "Ethernet tx queue setup fail\n");
            goto out;
        }
    }
    /**
     * Let's start the ethernet device and begin to receive packets
     */
    ret = rte_eth_dev_start(port);
    if (ret < 0) {
        fprintf(stderr, "Ethernet device start fail\n");
        goto out;
    }

    /**
     * Then go into promiscuous mode
     */
    rte_eth_promiscuous_enable(port);

    /**
     * Then receive any multicast ethernet frame
     */
    rte_eth_allmulticast_enable(port);


    /* rss info */
    struct rte_eth_rss_conf rss_conf;
    rss_conf.rss_key_len = 40;
    rss_conf.rss_key = malloc(sizeof(uint8_t) * dev_info.hash_key_size);
    rte_eth_dev_rss_hash_conf_get(port, &rss_conf);
    fprintf(stderr,"rx offload key len %u 0x%lx %u\n",
        rss_conf.rss_key_len, rss_conf.rss_hf, dev_info.hash_key_size);
    
    uint8_t i;
    for (i = 0; i < dev_info.hash_key_size; i++)
		fprintf(stderr,"%02X", rss_conf.rss_key[i]);
	printf("\n");
    free(rss_conf.rss_key);
  
out:
    return ret;
}

/**
 * Destroy an ethernet port
 */
static int di_ethport_exit(uint16_t port)
{
    rte_eth_dev_close(port);
    return 0;
}

/**
 * Launch packet processing on each lcore.
 * XXX Should be run be MASTER only
 */
static int di_run(void)
{
    unsigned int slavenb, lcoreid, lcid = 0;
    int ret = 0;
    uint16_t p;
    char qname[QNAMESZ] = {};

    /* convert to number of cycles */
    timer_cycles = timer_period * rte_get_timer_hz();

    slavenb = rte_lcore_count() - 1;

    /**
     * Get the number of ethernet NIC ports
     */
#if RTE_VERSION > RTE_VERSION_NUM(19, 11, 0, 0)
    port_nb = rte_eth_dev_count_avail();
#else
    port_nb = rte_eth_dev_count();
#endif
    if (port_nb == 0) {
        fprintf(stderr, "No probed ether devices check config\n");
        ret = -ENODEV;
        goto out;
    }

    /**
     * Enable all dpdk port
     */
    for (p = 0; p < port_nb; ++p) {
        ret = di_ethport_init(p);
        if (ret < 0) {
            port_nb = p;
            goto out;
        }
    }

    g_lcore = calloc(slavenb, sizeof(struct lcore));
    if (g_lcore == NULL) {
        goto out;
    }

    hz = rte_get_timer_hz();
    gettimeofday(&start_time, NULL);
    starting_cycles = rte_get_timer_cycles();

    /**
     * Launch packet loop on each lcore except MASTER. This function will
     * first check that each SLAVE lcore are in WAIT state the call
     * rte_eal_remote_launch() for each one.
     **/
    RTE_LCORE_FOREACH_SLAVE(lcoreid) {
        g_lcore[lcid].id = lcid;
        g_lcore[lcid].cpu_id= lcoreid;
        if (lcoreid > g_worker) {
            snprintf(qname, QNAMESZ - 1, QNAMEPREFIX"%u", lcid);
            g_lcore[lcid].queue = rte_ring_create(qname, swsize, rte_lcore_to_socket_id(lcid), RING_F_SC_DEQ);
            fprintf(stderr, "%p %s %d %d\n",g_lcore[lcid].queue, qname, lcoreid, lcid);
            if (g_lcore[lcid].queue == NULL) {
                goto out;
            }
        }
        else {
            g_lcore[lcid].queue = NULL;
            
        }
        rte_eal_remote_launch(di_pkt_loop, (void *)&g_lcore[lcid], lcoreid);
        ++lcid;
    }

    /**
     * Dispatch packet for every body
     */
    di_master_loop(g_lcore, port_nb);

    /**
     * Wait all lcore to finish and put them into WAIT state
     */
    rte_eal_mp_wait_lcore();

    di_stats_print(g_lcore, slavenb, port_nb);

    free(g_lcore);

out:

    /**
     * Disable all dpdk port
     */
    for (p = 0; p < port_nb; ++p) {
        di_ethport_exit(p);
    }

    return ret;
}

static void di_setup_detection(u_int16_t thread_id)
{
    NDPI_PROTOCOL_BITMASK all;
    struct ndpi_workflow_prefs prefs;
    memset(&prefs, 0, sizeof(prefs));
    prefs.decode_tunnels = 0;
    prefs.num_roots = 512;
    prefs.max_ndpi_flows = 200000000;
    prefs.quiet_mode = 0;
    prefs.ignore_vlanid = 0;
    memset(&ndpi_thread_info[thread_id], 0, sizeof(ndpi_thread_info[thread_id]));
    ndpi_thread_info[thread_id].workflow = ndpi_workflow_init(&prefs, NULL);
    // enable all protocols 
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].workflow->ndpi_struct, &all);

    // clear memory for results
    memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter, 0,
        sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter));
    memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes, 0,
        sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes));
    memset(ndpi_thread_info[thread_id].workflow->stats.protocol_flows, 0,
        sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_flows));

    ndpi_finalize_initialization(ndpi_thread_info[thread_id].workflow->ndpi_struct);
    
}

static int di_dpi_init(void)
{
    long thread_id;

    if (ndpi_get_api_version() != NDPI_API_VERSION) {
      printf("nDPI Library version mismatch:please make sure this code and the nDPI"
        " library are in sync\n");
      return(-1);
    }
    
    for(thread_id = 0; thread_id < dpi_workers; thread_id++) {
        di_setup_detection(thread_id);
    }
    printf("flow size %ld\n",sizeof(ndpi_flow_info_t));
    return 0;
}

static int di_dpi_exit(void)
{
    return 0;
}

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
static int
di_parse_timer_period(const char *q_arg)
{
    char *end = NULL;
    int n;

    /* parse number string */
    n = strtol(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0')) {
        return -1;
    }
    if (n >= MAX_TIMER_PERIOD) {
        return -1;
    }
    return n;
}

/**
 * Parse non dpdk only arguments
 */
static int di_parse_args(int argc, char **argv)
{
    int i;
    if (argc < 2) {
        return -1;
    }

    for (i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--") == 0) {
            ++i;
            break;
        }
    }

    if (i >= argc) {
        return 0;
    }

    for (; i < argc; ++i) {
        if (strcmp(argv[i], "--nic_ring_size") == 0) {
            ++i;
            if (i >= argc) {
                return -1;
            }
            hwsize = atoi(argv[i]);
            continue;
        } else if (strcmp(argv[i], "--dpi_ring_size") == 0) {
            ++i;
            if (i >= argc) {
                return -1;
            }
            swsize = atoi(argv[i]);
            continue;
        } else if (strcmp(argv[i], "--nb_flows") == 0) {
            ++i;
            if (i >= argc) {
                return -1;
            }
            nb_flows_arg = atoi(argv[i]);
            continue;
        } else if (strcmp(argv[i], "--enable-monitoring") == 0) {
            monitoring = 1;
            continue;
        } else if (strcmp(argv[i], "--no-print") == 0) {
            noprint = 1;
            continue;
        } else if (strcmp(argv[i], "--timer") == 0) {
            ++i;
            if (i >= argc) {
                return -1;
            }
            timer_period = di_parse_timer_period(argv[i]);
            if (timer_period < 0) {
                fprintf(stderr, "invalid timer period\n");
                return -1;
            }
            continue;
        } else if (strcmp(argv[i], "--receiver") == 0) {
            ++i;
            if (i >= argc) {
                return -1;
            }
            g_worker = atoi(argv[i]);
            continue;
        } 
        else if (strcmp(argv[i], "--hash") == 0) {
            ++i;
            if (i >= argc) {
                return -1;
            }
            g_hash_method = atoi(argv[i]);
            continue;
        } else {
            return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;

    ret = di_parse_args(argc, argv);
    if (ret != 0) {
        usage(argv[0]);
        ret = 1;
        goto exit;
    }

    ret = di_app_init(argc, argv);
    if (ret != 0) {
        ret = 1;
        goto exit;
    }

    ret = di_dpi_init();
    if (ret != 0) {
        ret = 1;
        goto appexit;
    }

    di_run();

    di_dpi_exit();

appexit:
    ret = di_app_exit();
    if (ret < 0) {
        return 1;
    }

exit:
    return ret;
}
