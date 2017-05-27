#include <arpa/inet.h>
#include <assert.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/dlt.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pcap_t *hpcap_handle;
static char g_hostname[1024];
static char error_descr[PCAP_ERRBUF_SIZE];
static int snaplen = 0;
static mach_timebase_info_data_t g_timebaseInfo;
static uint64_t g_mach_time_start;

/* Taken from APPLE xnu-3789.51.2 if_pglog.h */
#define PFLOG_RULESET_NAME_SIZE 16

struct pfloghdr {
  u_int8_t length;
  sa_family_t af;
  u_int8_t action;
  u_int8_t reason;
  char ifname[IFNAMSIZ];
  char ruleset[PFLOG_RULESET_NAME_SIZE];
  u_int32_t rulenr;
  u_int32_t subrulenr;
  uid_t uid;
  pid_t pid;
  uid_t rule_uid;
  pid_t rule_pid;
  u_int8_t dir;
  u_int8_t pad[3];
};

static const char *const PFDIR_NAMES[] = {"in/out", "in", "out", NULL};
static const uint32_t PFDIR_NAMES_SIZE = 3;

static const char *const PFACTION_NAMES[] = {
    "pass",       "drop",    "scrub",   "noscrub", "nat",           "nonat",
    "binat",      "nobinat", "rdr",     "nordr",   "synproxy_drop", "dummynet",
    "nodummynet", "nat64",   "nonat64", NULL};
static const uint32_t PFACTION_NAMES_SIZE = 15;

static const char *const PFRES_NAMES[] = {
    "match",       "bad-offset",  "fragment",       "short",
    "normalize",   "memory",      "bad-timestamp",  "congestion",
    "ip-option",   "proto-cksum", "state-mismatch", "state-insert",
    "state-limit", "src-limit",   "synproxy",       "dummynet",
    NULL};
static const uint32_t PFRES_NAMES_SIZE = 16;

static const char *idx2name(uint32_t idx, const char *const *tbl,
                            uint32_t limit) {
  if (idx >= limit) {
    return "unkn";
  }
  return tbl[idx];
}

#define TO_NSEC_64(x) ((uint64_t)(x)*1000000000)

static bool get_ports(const void *transport_layer_packet, int ip_p,
                      uint16_t *src_port, uint16_t *dst_port) {
  assert(src_port);
  assert(dst_port);

  switch (ip_p) {
  case 6: { // TCP
    const struct tcphdr *const tcp_hdr =
        (const struct tcphdr *)(transport_layer_packet);

    unsigned short th_sport;
    memcpy(&th_sport, &tcp_hdr->th_sport, sizeof(tcp_hdr->th_sport));
    *src_port = ntohs(th_sport);

    unsigned short th_dport;
    memcpy(&th_dport, &tcp_hdr->th_dport, sizeof(tcp_hdr->th_dport));
    *dst_port = ntohs(th_dport);

    return true;
  }

  case 17: { // UDP
    const struct udphdr *const udp_hdp =
        (const struct udphdr *)(transport_layer_packet);

    unsigned short uh_sport;
    memcpy(&uh_sport, &udp_hdp->uh_sport, sizeof(udp_hdp->uh_sport));
    *src_port = ntohs(uh_sport);

    unsigned short uh_dport;
    memcpy(&uh_dport, &udp_hdp->uh_dport, sizeof(udp_hdp->uh_dport));
    *dst_port = ntohs(uh_dport);

    return true;
  }
  default:
    return false;
  }
}

static void process_packet(u_char *args, const struct pcap_pkthdr *header,
                           const u_char *packet) {
  (void)(args);
  (void)(header);
  if (*packet > sizeof(struct pfloghdr)) {
    printf("Packet size(%d) > pfloghdr size(%lu). Skipping packet...\n",
           *packet, sizeof(struct pfloghdr));
    return;
  }

  int sret = 0;
  uint32_t wr = 0;
  const uint64_t mach_time_end = mach_absolute_time();

  const uint64_t elapsedNano = (mach_time_end - g_mach_time_start) *
                               g_timebaseInfo.numer / g_timebaseInfo.denom;
  const uint32_t hour = elapsedNano / TO_NSEC_64(3600);
  const uint32_t min = elapsedNano / TO_NSEC_64(60);
  const uint32_t sec = (elapsedNano % TO_NSEC_64(60)) / 1000000000;
  const uint32_t usec = (elapsedNano % 1000000);

  char msg_buf[2048], *p;
  memset_s(msg_buf, sizeof(msg_buf), 0, sizeof(msg_buf));
  p = msg_buf;
  sret = snprintf(msg_buf, sizeof(msg_buf), "%.2u:%.2u:%.2u.%06u ", hour, min,
                  sec, usec);
  if (sret >= (int)sizeof(msg_buf) || -1 == sret)
    return;
  p += sret;
  wr += (uint32_t)(sret);

  struct pfloghdr packhdr;
  memcpy(&packhdr, packet, sizeof(packhdr));
  const struct pfloghdr *hdr = &packhdr; //(struct pfloghdr*)packet;

  if (hdr->subrulenr == (uint32_t)-1) {
    sret = snprintf(p, sizeof(msg_buf) - wr, "rule %u/", ntohl(hdr->rulenr));
  } else {
    sret = snprintf(p, sizeof(msg_buf) - wr, "rule %u.%s.%u/",
                    ntohl(hdr->rulenr), hdr->ruleset, ntohl(hdr->subrulenr));
  }
  if (sret >= (int)sizeof(msg_buf) || -1 == sret)
    return;
  p += sret;
  wr += (uint32_t)(sret);

  sret = snprintf(
      p, sizeof(msg_buf) - wr,
      "%s: %s %s on %s: ", idx2name(hdr->reason, PFRES_NAMES, PFRES_NAMES_SIZE),
      idx2name(hdr->action, PFACTION_NAMES, PFACTION_NAMES_SIZE),
      idx2name(hdr->dir, PFDIR_NAMES, PFDIR_NAMES_SIZE), hdr->ifname);
  if (sret >= (int)sizeof(msg_buf) || -1 == sret)
    return;
  p += sret;
  wr += (uint32_t)(sret);

  int proto_num = 0;

  if (AF_INET == hdr->af) {
    const struct ip *const ip_hdr =
        (const struct ip *)(packet + BPF_WORDALIGN(hdr->length));
    const uint32_t size_ip = ip_hdr->ip_hl * 4;

    if (size_ip < 20) {
      struct protoent *const proto_desc = getprotobynumber(ip_hdr->ip_p);
      const char *name = "";
      if (NULL != proto_desc) {
        name = proto_desc->p_name;
      }
      snprintf(p, sizeof(msg_buf) - wr,
               "Invalid IP header length: %u bytes, total len:%d, ttl:%d, "
               "proto:%d(%s)",
               size_ip, ip_hdr->ip_len, ip_hdr->ip_ttl, ip_hdr->ip_p, name);
      goto done;
    }

    struct in_addr ip_src, ip_dst;
    memcpy(&ip_src, &ip_hdr->ip_src, sizeof(ip_hdr->ip_src));
    memcpy(&ip_dst, &ip_hdr->ip_dst, sizeof(ip_hdr->ip_dst));

    const void *const transport_layer_packet =
        (packet + BPF_WORDALIGN(hdr->length) + size_ip);
    uint16_t src_port = 0, dst_port = 0;

    get_ports(transport_layer_packet, ip_hdr->ip_p, &src_port, &dst_port);

    sret = snprintf(p, sizeof(msg_buf) - wr, "%s(%u) -> %s(%u) - ",
                    inet_ntoa(ip_src), src_port, inet_ntoa(ip_dst), dst_port);
    if (sret >= (int)sizeof(msg_buf) || -1 == sret)
      return;
    p += sret;
    wr += (uint32_t)(sret);

    proto_num = ip_hdr->ip_p;

  } else if (AF_INET6 == hdr->af) {
    const struct ip6_hdr *ip_hdr =
        (const struct ip6_hdr *)(packet + BPF_WORDALIGN(hdr->length));

    const int ip_p = ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    const void *const transport_layer_packet =
        (packet + BPF_WORDALIGN(hdr->length) + sizeof(struct ip6_hdr));

    uint16_t src_port = 0, dst_port = 0;
    get_ports(transport_layer_packet, ip_p, &src_port, &dst_port);

    struct in6_addr ip6_src;
    memcpy(&ip6_src, &ip_hdr->ip6_src, sizeof(ip_hdr->ip6_src));

    struct in6_addr ip6_dst;
    memcpy(&ip6_dst, &ip_hdr->ip6_dst, sizeof(ip_hdr->ip6_dst));

    char ip6addr_s[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6_src, ip6addr_s, INET6_ADDRSTRLEN);

    char ip6addr_d[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6_dst, ip6addr_d, INET6_ADDRSTRLEN);

    sret = snprintf(p, sizeof(msg_buf) - wr, "%s(%u) -> %s(%u) - ", ip6addr_s,
                    src_port, ip6addr_d, dst_port);

    if (sret >= (int)sizeof(msg_buf) || -1 == sret)
      return;
    p += sret;
    wr += (uint32_t)(sret);

    proto_num = ip_p;
  }

  struct protoent *const proto_desc = getprotobynumber(proto_num);
  if (NULL != proto_desc) {
    sret = snprintf(p, sizeof(msg_buf) - wr, "%s", proto_desc->p_name);
    if (sret >= (int)sizeof(msg_buf) || -1 == sret)
      return;
    p += sret;
    wr += (uint32_t)(sret);

  } else {
    sret = snprintf(p, sizeof(msg_buf) - wr, "unknown");
    if (sret >= (int)sizeof(msg_buf) || -1 == sret)
      return;
    p += sret;
    wr += (uint32_t)(sret);
  }

done:
  strcat(msg_buf, "\n");
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  char date[128];
  strftime(date, sizeof(date) - 1, "%y-%m-%d %H:%M:%S ", t);

  char outstring[4096];
  strcpy(outstring, date);
  strcat(outstring, g_hostname);
  strcat(outstring, " pf ");
  strcat(outstring, msg_buf);

  fputs(outstring, stdout);
  fflush(stdout);

  g_mach_time_start = mach_absolute_time();
}

static void sig_handler_term(int sig) {
  printf("TERM(%d) received\n", sig);
  pcap_breakloop(hpcap_handle);
}

int main(int argc, char **argv) {
  // set pcap loop
  // printf for loggind
  // plist file

  if (argc < 2) {
    printf("Usage: %s <interface>\n", argv[0]);
    return EXIT_FAILURE;
  }

  int ret = EXIT_SUCCESS;
  const char *const interface = argv[1];

  gethostname(g_hostname, sizeof(g_hostname));
  signal(SIGTERM, sig_handler_term);

  // To detect warning message on open we set it to 0 length string
  memset_s(error_descr, sizeof(error_descr), 0, sizeof(error_descr));

  hpcap_handle = pcap_open_live(interface, BUFSIZ, 1, 400, error_descr);
  if (NULL == hpcap_handle) {
    printf("Failed to initialize: %s\n", error_descr);
    return EXIT_FAILURE;
  }

  if (strlen(error_descr) > 0) {
    printf("pcap_open_live warning: %s\n", error_descr);
  }

  const int link_type = pcap_datalink(hpcap_handle);
  if (PCAP_ERROR_NOT_ACTIVATED == link_type) {
    printf("Handle not activated\n");
    ret = EXIT_FAILURE;
    goto done;
  }

  if (DLT_PFLOG != link_type) {
    printf("Invalid datalink type: %d, expected:%d \n", link_type, DLT_PFLOG);
    ret = EXIT_FAILURE;
    goto done;
  }

  struct bpf_program bprog;
  // No filter programm is used
  const char *filter = NULL;

  if (pcap_compile(hpcap_handle, &bprog, filter, 1, 0) == -1) {
    pcap_perror(hpcap_handle, "pcap_compile failed:");
    ret = EXIT_FAILURE;
    goto done;

  } else {
    if (pcap_setfilter(hpcap_handle, &bprog) == -1) {
      pcap_perror(hpcap_handle, "pcap_setfilter failed:");
    }
    pcap_freecode(&bprog);
  }

  snaplen = pcap_snapshot(hpcap_handle);
  if (PCAP_ERROR_NOT_ACTIVATED == snaplen) {
    printf("pcap_snapshot: Handle not activated\n");
    ret = EXIT_FAILURE;
    goto done;
  }

  // If this is the first time we've run, get the timebase.
  // We can use denom == 0 to indicate that sTimebaseInfo is
  // uninitialised because it makes no sense to have a zero
  // denominator is a fraction.

  if (g_timebaseInfo.denom == 0) {
    (void)mach_timebase_info(&g_timebaseInfo);
  }
  g_mach_time_start = mach_absolute_time();

  printf("Starting pflogd pcap loop\n");
  ret = pcap_loop(hpcap_handle, -1, process_packet, NULL);
  if (-1 == ret) {
    pcap_perror(hpcap_handle, "pcap_loop failed:");
  }

done:
  pcap_close(hpcap_handle);
  return ret;
}
