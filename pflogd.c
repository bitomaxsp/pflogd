#include <pcap/dlt.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pcap_t* hpcap_handle;
static char hostname[1024];
static struct timeval g_time;
static char msg_buf[4096];
static char error_descr[PCAP_ERRBUF_SIZE];
static int snaplen = 0;

static void
process_packet(u_char* args,
               const struct pcap_pkthdr* header,
               const u_char* packet)
{
}

static void
sig_handler_term(int sig)
{
  printf("TERM received\n");
  pcap_breakloop(hpcap_handle);
}

int
main(int argc, char** argv)
{
  // set pcap loop
  // printf for loggind
  // plist file

  if (argc < 2) {
    printf("Usage: %s <interface>\n", argv[0]);
    return EXIT_FAILURE;
  }

  int ret = EXIT_SUCCESS;
  const char* const interface = argv[1];

  gethostname(hostname, sizeof(hostname));
  gettimeofday(&g_time, NULL);
  signal(SIGTERM, sig_handler_term);
  memset_s(msg_buf, sizeof(msg_buf), 0, sizeof(msg_buf));

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
  const char* filter = NULL;

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

  printf("Starting pflogd pcap loop\n");
  ret = pcap_loop(hpcap_handle, -1, process_packet, NULL);
  if (-1 == ret) {
    pcap_perror(hpcap_handle, "pcap_loop failed:");
  }

done:
  pcap_close(hpcap_handle);
  return ret;
}
