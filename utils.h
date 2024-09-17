typedef pcap_t *pcap_handle;
typedef struct pcap_pkthdr pcap_pkthdr;
typedef struct pcap_stat pcap_stat;
typedef struct bpf_program *bpf_program;
typedef struct pcap_dumper *pcap_dumper;
typedef struct pcap_if pcap_if;

typedef FILE *file_t;

typedef void (*pcap_callback)(u_char *, const struct pcap_pkthdr *,
		                                 const u_char *);

void pcap_dump_direct(pcap_dumper,pcap_pkthdr *, unsigned char *);


void _pcap_callback (void *, va_alist);

value build_pcap_if_array (pcap_if *);
value camlidl_pcap_pcap_findalldevs(value);

