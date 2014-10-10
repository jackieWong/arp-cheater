#include <pcap.h>

struct eth_header
{
	u_int8_t ether_dhost[6];
	u_int8_t ether_shost[6];
	u_int16_t ether_type;
};

int main(int argc, char **argv)
{
	//char *dev = argv[1];
	//printf("Device: %s\n", dev);
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;
	bpf_u_int32 net;

	dev = pcap_lookupdev(errbuf);

	if(dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	}
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	pcap_t *handle;
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL) {
		fprintf(stderr,"Couldn't open device %s", dev);
		return(2);
	}
	
	printf("Device: %s\n", dev);
	printf("IP:%08x\n", net);
	printf("NetMask:%08x\n",mask); 
	char filter_exp[] = "arp";
	struct bpf_program fp;

	if (pcap_compile(handle, &fp, filter_exp, 0 ,net) == -1){
		fprintf(stderr, "Couldn't parse filter %s %s\n", filter_exp, pcap_geterr(handle));
	}

	if (pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "Couldn't install filter %s %s\n", filter_exp,
	pcap_geterr(handle));
	}
	
	const u_char *packet;
	struct pcap_pkthdr header;	
	packet = pcap_next(handle, &header);
	printf("packet header length: %u\n", header.len);

	struct eth_header *eptr = (struct eth_header *) packet;
	
	printf("Ethernet type hex:%x \n", ntohs(eptr->ether_type));
	printf("Dest host:%x:%x:%x:%x:%x:%x\n", eptr->ether_dhost[0],
		eptr->ether_dhost[1],
		eptr->ether_dhost[2],
		eptr->ether_dhost[3],
		eptr->ether_dhost[4],
		eptr->ether_dhost[5]);
 
	printf("Src host:%x:%x:%x:%x:%x:%x\n", eptr->ether_shost[0],
		eptr->ether_shost[1],
		eptr->ether_shost[2],
		eptr->ether_shost[3],
		eptr->ether_shost[4],
		eptr->ether_shost[5]);
		


	//for(i = 0 ; i < header.len; i++) {
	//	nprintf("%x", packet,);	
	//}	
	pcap_close(handle);
	return 0;
}
