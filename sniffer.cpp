#include <iostream>
#include <stdio.h>
#include <WinSock2.h>
#include <winsock.h>

#pragma comment(lib, "ws2_32.lib") // Для работы winsock

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) // Удаляет необходимость в mstcpip.h

#define HOSTNAME_LENGTH 1024

void StartSniffing (SOCKET Sock); 

void ProcessPacket (char*, int);
void PrintIpHeader (char*);
void PrintIcmpPacket (char*, int);
void PrintUdpPacket (char*, int);
void PrintTcpPacket (char*, int);
void ConvertToHex (char*, unsigned int);
void PrintData (char*, int);

// IP header
typedef struct ip_header
{
	unsigned char ipHeaderLength: 4;
	unsigned char ipVersion: 4; 
	unsigned char ipTOS; 
	unsigned short ipTotalLength; 
	unsigned short ipID; 

	unsigned char ipFragmentOffset: 5; // Сдвиг фрагмента

	unsigned char ipMoreFragment: 1;
	unsigned char ipDontFragment: 1;
	unsigned char ipReservedZero: 1;

	unsigned char ipFragmentOffset1; // Сдвиг фрагмента

	unsigned char ipTimeToLive; // Время жизни 
	unsigned char ipProtocol; // Протокол 
	unsigned short ipChecksum; // IP Checksum
	unsigned int ipSrcAddress; // Исходный адрес
	unsigned int ipDestAddress; // Адрес назначения
} IPv4_HDR;

// UDP header
typedef struct udp_header
{
	unsigned short srcPort; // Source port no.
	unsigned short destPort; // Dest. port no.
	unsigned short udpLength; // Udp packet length
	unsigned short udpChecksum; // Udp checksum (optional)
} UDP_HDR;

// TCP header
typedef struct tcp_header
{
	unsigned short srcPort; // source port
	unsigned short destPort; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns: 1; 
	unsigned char reservedPart1: 3; 
	unsigned char dataOffset: 4; 

	unsigned char fin: 1; // Finish Flag
	unsigned char syn: 1; // Synchronise Flag
	unsigned char rst: 1; // Reset Flag
	unsigned char psh: 1; // Push Flag
	unsigned char ack: 1; // Acknowledgement Flag
	unsigned char urg: 1; // Urgent Flag

	unsigned char ecn: 1; // ECN-Echo Flag
	unsigned char cwr: 1; // Congestion Window Reduced Flag

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgentPointer; // urgent pointer
} TCP_HDR;

// ICMP header
typedef struct icmp_header
{
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;

FILE *logfile;
int tcp = 0, udp = 0,icmp = 0, others = 0, total = 0, i, j;
struct sockaddr_in source, dest;
char hex[2];

IPv4_HDR *ipHdr;
TCP_HDR *tcpHdr;
UDP_HDR *udpHdr;
ICMP_HDR *icmpHdr;

int main()
{
	SOCKET sock;
	struct in_addr addr;
	int in;

	char hostname[HOSTNAME_LENGTH];
	struct hostent *localHost;
	WSADATA wsaData;

	logfile = fopen("log.txt", "w");
	if(logfile == NULL) {
        std::cerr << "Error: Unable to create file.\n";
        return 1;
	}

	// Инициализируем winsock
	if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        std::cerr << "Error: WSAStartup() failed.\n";
        WSACleanup();
		return 1;
	}

	// Создаем сырой сокет
	if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == INVALID_SOCKET) {
        std::cerr << "Error: Failed to create a raw socket.\n";
        WSACleanup();
		return 1;
	}

	// Получаем имя пользователя
	if(gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        std::cerr << "Error: " << WSAGetLastError() << '\n';
        WSACleanup();
		return 1;
	}

    // Проверка ошибки получения хоста 
	localHost = gethostbyname(hostname);
	if(localHost == NULL) {
        std::cerr << "Error: " << WSAGetLastError() << '\n';
        WSACleanup();
		return 1;
	}

    // Получаем IP доступные для пользователя
	printf("\nAvailable Network Interfaces: \n");
	for (i = 0; localHost->h_addr_list[i] != 0; ++i) {
		memcpy(&addr, localHost->h_addr_list[i], sizeof(struct in_addr));
		printf("Interface Number: %d Address: %s\n", i, inet_ntoa(addr));
	}

	printf("Enter the interface to sniff: ");
	scanf("%d", &in);

	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, 
           localHost->h_addr_list[in],
           sizeof(dest.sin_addr.s_addr));

	dest.sin_family = AF_INET;
	dest.sin_port = 0;

    // Связываем сокет с адресом
	if(bind(sock, (struct sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR) {
		printf("Erorr: bind(%s) failed.\n", inet_ntoa(addr));
        WSACleanup();
		return 1;
	}

    // Настраиваем сокет для анализа
    j = 1;
	if(WSAIoctl(sock, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in, 0, 0) == SOCKET_ERROR) {
		printf("Error: setting socket failed.\n");
        WSACleanup();
		return 1;
	}

    // Начинаем анализ
    printf("Sniffering...");
	StartSniffing(sock);

    // Заканчиваем анализ
	closesocket(sock);
	WSACleanup();

	return 0;
}

void StartSniffing(SOCKET sock)
{
	char *buffer = (char *)malloc(65536);
	int mangobyte;

	if(buffer == NULL) {
		printf("Error: malloc() failed.\n");
		return;
	}

	do {
		mangobyte = recvfrom(sock, buffer, 65535, 0, 0, 0);

		if(mangobyte > 0) {
			ProcessPacket(buffer, mangobyte);
		} else {
			printf("Error: recvfrom() failed.\n");
		}
	} while (mangobyte > 0);

	free(buffer);
}

void ProcessPacket(char *buffer, int size)
{
	ipHdr = (IPv4_HDR*)buffer;
	++total;

	switch (ipHdr->ipProtocol) {
    case 1: // ICMP Протокол 
		++icmp;
		PrintIcmpPacket(buffer,size);
		break;

    case 6: // TCP Протокол 
		++tcp;
		PrintTcpPacket(buffer,size);
		break;

    case 17: // UDP Протокол 
		++udp;
		PrintUdpPacket(buffer,size);
		break;

    default: // Другие протоколы
		++others;
		break;
	}
	printf("TCP: %d UDP: %d ICMP: %d OTHERS: %d TOTAL: %d\r", 
            tcp, udp, icmp, others, total);
}

void PrintIpHeader(char *buffer)
{
	unsigned short ipHdrLen;

	ipHdr = (IPv4_HDR*)buffer;
	ipHdrLen = ipHdr->ipHeaderLength*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ipHdr->ipSrcAddress;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ipHdr->ipDestAddress;

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, " |-IP Version: %d\n", (unsigned int)ipHdr->ipVersion);
	fprintf(logfile, " |-IP Header Length: %d DWORDS or %d Bytes\n", (unsigned int)ipHdr->ipHeaderLength, ((unsigned int)(ipHdr->ipHeaderLength))*4);
	fprintf(logfile, " |-Type Of Service: %d\n", (unsigned int)ipHdr->ipTOS);
	fprintf(logfile, " |-IP Total Length: %d Bytes(size of Packet)\n", ntohs(ipHdr->ipTotalLength));
	fprintf(logfile, " |-Identification: %d\n", ntohs(ipHdr->ipID));
	fprintf(logfile, " |-Reserved ZERO Field: %d\n", (unsigned int)ipHdr->ipReservedZero);
	fprintf(logfile, " |-Dont Fragment Field: %d\n", (unsigned int)ipHdr->ipDontFragment);
	fprintf(logfile, " |-More Fragment Field: %d\n", (unsigned int)ipHdr->ipMoreFragment);
	fprintf(logfile, " |-TTL: %d\n", (unsigned int)ipHdr->ipTimeToLive);
	fprintf(logfile, " |-Protocol: %d\n", (unsigned int)ipHdr->ipProtocol);
	fprintf(logfile, " |-Checksum: %d\n", ntohs(ipHdr->ipChecksum));
	fprintf(logfile, " |-Source IP: %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, " |-Destination IP: %s\n", inet_ntoa(dest.sin_addr));
}

void PrintTcpPacket(char* buffer, int size)
{
	unsigned short ipHdrLen;

	ipHdr = (IPv4_HDR*)buffer;
	ipHdrLen = ipHdr->ipHeaderLength*4;

	tcpHdr=(TCP_HDR*)(buffer+ipHdrLen);

	fprintf(logfile, "\n\n***********************TCP Packet*************************\n");

	PrintIpHeader(buffer );

	fprintf(logfile, "\n");
	fprintf(logfile, "TCP Header\n");
	fprintf(logfile, " |-Source Port: %u\n", ntohs(tcpHdr->srcPort));
	fprintf(logfile, " |-Destination Port: %u\n", ntohs(tcpHdr->destPort));
	fprintf(logfile, " |-Sequence Number: %u\n", ntohl(tcpHdr->sequence));
	fprintf(logfile, " |-Acknowledge Number: %u\n", ntohl(tcpHdr->acknowledge));
	fprintf(logfile, " |-Header Length: %d DWORDS or %d BYTES\n",
           (unsigned int)tcpHdr->dataOffset, (unsigned int)tcpHdr->dataOffset*4);
	fprintf(logfile, " |-CWR Flag: %d\n", (unsigned int)tcpHdr->cwr);
	fprintf(logfile, " |-ECN Flag: %d\n", (unsigned int)tcpHdr->ecn);
	fprintf(logfile, " |-Urgent Flag: %d\n", (unsigned int)tcpHdr->urg);
	fprintf(logfile, " |-Acknowledgement Flag: %d\n", (unsigned int)tcpHdr->ack);
	fprintf(logfile, " |-Push Flag: %d\n", (unsigned int)tcpHdr->psh);
	fprintf(logfile, " |-Reset Flag: %d\n", (unsigned int)tcpHdr->rst);
	fprintf(logfile, " |-Synchronise Flag: %d\n", (unsigned int)tcpHdr->syn);
	fprintf(logfile, " |-Finish Flag: %d\n", (unsigned int)tcpHdr->fin);
	fprintf(logfile, " |-Window: %d\n", ntohs(tcpHdr->window));
	fprintf(logfile, " |-Checksum: %d\n", ntohs(tcpHdr->checksum));
	fprintf(logfile, " |-Urgent Pointer: %d\n", tcpHdr->urgentPointer);
	fprintf(logfile, "\n");
	fprintf(logfile, " DATA Dump ");
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData(buffer, ipHdrLen);

	fprintf(logfile, "TCP Header\n");
	PrintData(buffer + ipHdrLen, tcpHdr->dataOffset*4);

	fprintf(logfile, "Data Payload\n");
	PrintData(buffer + ipHdrLen + tcpHdr->dataOffset*4,
             (size - tcpHdr->dataOffset*4 - ipHdr->ipHeaderLength*4));

	fprintf(logfile, "\n====================================");
}

void PrintUdpPacket(char *buffer,int size)
{
	unsigned short ipHdrLen;

	ipHdr = (IPv4_HDR*)buffer;
	ipHdrLen = ipHdr->ipHeaderLength*4;

	udpHdr = (UDP_HDR*)(buffer+ipHdrLen);

	fprintf(logfile, "\n\n-----------------------UDP Packet-------------------------\n");

	PrintIpHeader(buffer);

	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, " |-Source Port: %d\n", ntohs(udpHdr->srcPort));
	fprintf(logfile, " |-Destination Port: %d\n", ntohs(udpHdr->destPort));
	fprintf(logfile, " |-UDP Length: %d\n", ntohs(udpHdr->udpLength));
	fprintf(logfile, " |-UDP Checksum: %d\n", ntohs(udpHdr->udpChecksum));

	fprintf(logfile, "\nIP Header\n");

	PrintData(buffer, ipHdrLen);

	fprintf(logfile, "UDP Header\n");
	PrintData(buffer + ipHdrLen, sizeof(UDP_HDR));

	fprintf(logfile, "Data Payload\n");
	PrintData(buffer + ipHdrLen + sizeof(UDP_HDR),
             (size - sizeof(UDP_HDR) - ipHdr->ipHeaderLength*4));

	fprintf(logfile, "\n====================================");
}

void PrintIcmpPacket(char* buffer, int size)
{
	unsigned short ipHdrLen;

	ipHdr = (IPv4_HDR*)buffer;
	ipHdrLen = ipHdr->ipHeaderLength*4;

	icmpHdr = (ICMP_HDR*)(buffer+ipHdrLen);

	fprintf(logfile, "\n\n------------------------ICMP Packet-------------------------\n");
	PrintIpHeader(buffer);

	fprintf(logfile, "\nICMP Header\n");
	fprintf(logfile, " |-Type: %d", (unsigned int)(icmpHdr->type));

	if((unsigned int)(icmpHdr->type)==11) {
		fprintf(logfile, " (TTL Expired)\n");
	} else if((unsigned int)(icmpHdr->type)==0) {
		fprintf(logfile, " (ICMP Echo Reply)\n");
	}

	fprintf(logfile, " |-Code: %d\n", (unsigned int)(icmpHdr->code));
	fprintf(logfile, " |-Checksum: %d\n", ntohs(icmpHdr->checksum));
	fprintf(logfile, " |-ID: %d\n", ntohs(icmpHdr->id));
	fprintf(logfile, " |-Sequence: %d\n", ntohs(icmpHdr->seq));
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData(buffer, ipHdrLen);

	fprintf(logfile, "UDP Header\n");
	PrintData(buffer + ipHdrLen, sizeof(ICMP_HDR));

	fprintf(logfile, "Data Payload\n");
	PrintData(buffer + ipHdrLen + sizeof(ICMP_HDR), 
             (size - sizeof(ICMP_HDR) - ipHdr->ipHeaderLength*4));

	fprintf(logfile, "\n====================================");
}

void PrintData (char *data, int size)
{
	char a, line[17], c;
	int j;

	//loop over each character and print
	for(i = 0; i < size; i++)
	{
		c = data[i];

		//Print the hex value for every character, with a space. Important to make unsigned
		fprintf(logfile, " %.2x", (unsigned char) c);

		//Add the character to data line. Important to make unsigned
		a = (c >=32 && c <=128) ? (unsigned char) c: '.';

		line[i%16] = a;

		//if last character of a line, then print the line - 16 characters in 1 line
		if((i!=0 && (i+1)%16==0) || i == size - 1)
		{
			line[i%16 + 1] = '\0';

			//print a big gap of 10 characters between hex and characters
			fprintf(logfile, "          ");

			//Print additional spaces for last lines which might be less than 16 characters in length
			for(j = strlen(line); j < 16; j++)
			{
				fprintf(logfile, "   ");
			}

			fprintf(logfile, "%s \n", line);
		}
	}

	fprintf(logfile, "\n");
}

