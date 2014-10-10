#include <pcap/pcap.h>

int main(int argc, char **argv)
{
	//char *dev = argv[1];
	//printf("Device: %s\n", dev);
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	dev = pcap_lookupdev(errbuf);

	if(dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	}

	printf("Device: %s\n", dev);
	return 0;
}
