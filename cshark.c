#include <pcap.h>
#include <stdio.h>

pcap_t *handle;

struct sniff_ethernet {
  u_char ether_dhost[6];
  u_char ether_shost[6];
  u_short ether_type;
};

struct sniff_ip {
  u_char ip_vhl;
  u_char ip_tos;
  u_short ip_len;
  u_short ip_id;
  u_short ip_off;
  u_char ip_tol;
  u_char ip_protocol;
  u_short ip_chksum;
  u_char ip_src[4];
  u_char ip_dst[4];
};

#define SIZE_ETHERNET 14

struct bpf_program fp;
char filter_exp[] = "";
bpf_u_int32 mask;
bpf_u_int32 net;
struct pcap_pkthdr header;
const u_char *packet;
const struct sniff_ethernet *ethernet;
const struct sniff_ip *ip;

int main(int argc, char *argv[]) {
  char *dev, errbuf[PCAP_ERRBUF_SIZE];

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Could'nt find device: %s\n", errbuf);
  }
  printf("Device:%s\n", dev);

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device: %s: %s\n", dev, errbuf);
    return (2);
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s", filter_exp, pcap_geterr(handle));
    return (2);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s", filter_exp, pcap_geterr(handle));
    return (2);
  }

  while (1) {
    packet = pcap_next(handle, &header);
    if (header.len > 0) {
      break;
    }
  }
  printf("Jacked a packet with length of [%d]\n", header.len);

  ethernet = (struct sniff_ethernet*)(packet);
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

  printf("%d.%d.%d.%d -> %d.%d.%d.%d",
         (ip)->ip_src[0], (ip)->ip_src[1],(ip)->ip_src[2],(ip)->ip_src[3],
         (ip)->ip_dst[0], (ip)->ip_dst[1],(ip)->ip_dst[2],(ip)->ip_dst[3]);

  pcap_close(handle);
  return(0);
}

int plugin_is_GPL_compatible;

