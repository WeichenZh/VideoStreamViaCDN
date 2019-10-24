# include <stdio.h>
# include <string.h>
# include <iostream>
# include <typeinfo>
# include <stdlib.h>
# include <stdint.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <unistd.h>
# include "../starter_files/DNSHeader.h"
# include "../starter_files/DNSQuestion.h"
# include "../starter_files/DNSRecord.h"

#define MAXLINE 512 

using namespace std;
typedef uint8_t BYTE;

void error(const char *msg)
{
	perror(msg);
    exit(1);
}

int SendDndQueryPack(int *psockfd, ushort TransID, char *domainName, char *DNSaddr, ushort portno)
{
	if (*psockfd < 0
		|| !domainName
		|| !DNSaddr
		|| !strlen(domainName)
		|| !strlen(DNSaddr)
		|| portno <0)
		error("Error: Invalid argument for function::SendDndQueryPack()\n");

    char buffer[MAXLINE] = {0};
    DNSHeader queryHeader;
    DNSQuestion queryQuestion;
    string sQueryHeader, sQueryQuestion;
    int DNSHeader_size=0, DNSQuestion_size=0;
    int nSent = 0;

    // Encoding  Header
    memset(&queryHeader, 0, sizeof(queryHeader));
	 // Encoding Header
    queryHeader.ID = htons(TransID);  // ID
    queryHeader.QR = 0x0;
    queryHeader.AA = 0x0;
    queryHeader.RA = 0x0;
    queryHeader.RD = 0x0;
    queryHeader.Z = 0x0;  
    queryHeader.QDCOUNT = htons(0x1);  //I set it to 1 because so far I just assume that only 1 																//domain name will be asked per DNS package.
    queryHeader.ANCOUNT = htons(0x0);
    queryHeader.NSCOUNT = htons(0x0);
    queryHeader.ARCOUNT = htons(0X0);

    // Encoding Question:  name + type + class
    memset(&queryQuestion, 0, sizeof(queryQuestion));
    memcpy(queryQuestion.QNAME, domainName, strlen(domainName));
    queryQuestion.QTYPE = htons(0x1);
    queryQuestion.QCLASS = htons(0x1); 

    // prepare for sending
    sockaddr_in dnsServAddr;
    bzero((char *) &dnsServAddr, sizeof(dnsServAddr));
    dnsServAddr.sin_family = AF_INET;
    dnsServAddr.sin_port = htons(portno);  // DNS server port default is 53
    dnsServAddr.sin_addr.s_addr = inet_addr(DNSaddr);

    if (connect(*psockfd, (struct sockaddr *)&dnsServAddr,sizeof(dnsServAddr)) < 0)
        error("ERROR connecting");

    // encoding Header and Question
    sQueryHeader = DNSHeader::encode(queryHeader);
    sQueryQuestion = DNSQuestion::encode(queryQuestion);
    DNSHeader_size = htonl(sQueryHeader.length());
    DNSQuestion_size = htonl(sQueryQuestion.length());
    nSent = 0;

    // send size of DNS header
    nSent = send(*psockfd,
        (char*)&DNSHeader_size,
        sizeof(DNSHeader_size),
        0);

    memset(buffer, 0, MAXLINE);
    memcpy(buffer, sQueryHeader.c_str(), ntohl(DNSHeader_size));
    nSent = send(*psockfd,
        (char *)buffer,
        ntohl(DNSHeader_size),
        0);

    nSent = send(*psockfd, 
        (char *)&DNSQuestion_size,
        sizeof(DNSQuestion_size),
        0);

    memset(buffer, 0, MAXLINE);
    memcpy(buffer, sQueryQuestion.c_str(), ntohl(DNSQuestion_size));
    nSent = send(*psockfd,
        (char *)buffer,
        ntohl(DNSQuestion_size),
        0);

    return 0;
}

int RecvDnsPack(int *psockfd, ushort TransID, char *pDomainAddr)
{
	if (*psockfd < 0 
		|| !pDomainAddr)
		error("Error: invalid argument for function::RecvDnsPack()\n");

	char buffer[MAXLINE] = {0};
	sockaddr_in servAddr = {0};
    socklen_t len = sizeof(servAddr);
    int n_recv = 0;

    DNSHeader answerHeader;
    DNSRecord answerRecord;

    // receive the size of header
    int DNSHeader_size;
    memset(buffer, 0, MAXLINE);
    n_recv = recv(*psockfd,(char *)buffer,sizeof(DNSHeader_size),0);
    if (n_recv < 0)
    	error("Error reading from socket\n");
    memcpy(&DNSHeader_size, (BYTE *)buffer, sizeof(DNSHeader_size));
    DNSHeader_size = ntohl(DNSHeader_size);
    if(DNSHeader_size<=0)
        error("Error: DNS header size must be greater than zero\n");

     // receive DNS header
    memset(buffer, 0, MAXLINE);
    n_recv = recv(*psockfd,(char *)buffer,DNSHeader_size,0);
    if (n_recv < 0)
        error("Error: reading from socket\n");

    // Decoding Answer Header
    answerHeader = DNSHeader::decode(string(buffer));
    if (answerHeader.ID != htons(TransID))
    		error("Error: Query package ID is not consistent with Answer package ID\n");
    if (answerHeader.AA != 0x1)
    	error("Error: the package is not Answer package\n");
    if (answerHeader.RCODE != 0x0)
    {
    	if (answerHeader.RCODE == 0x3)
    	{
    		cout << "The IP address of querying server doesn\'t exist" <<endl;
    		return 0;
    	}
    }

    // receive DNS record size
    int DNSRecord_size;
    memset(buffer, 0, MAXLINE);
    n_recv = recv(*psockfd,(char *)buffer,sizeof(DNSRecord_size),0);
    if (n_recv<0)
        error("ERROR reading from socket\n");
    memcpy(&DNSRecord_size, (BYTE *)buffer, sizeof(DNSRecord_size));
    DNSRecord_size = ntohl(DNSRecord_size);
    if (DNSRecord_size<=0)
        error("Error: DNS record size must be greater than 0\n");

    // receive DNS record
    memset(buffer, 0, MAXLINE);
    n_recv = recv(*psockfd,(char *)buffer,DNSRecord_size,0);
    if (n_recv < 0)
        error("Error reading from socket\n");

    // Decoding Answer Record
    answerRecord = DNSRecord::decode(buffer);
    if (answerRecord.TYPE != htons(0x1))
    	error("Error: Record type should be 1\n");

   	if (answerRecord.CLASS != htons(0x1))
    	error("Error: Record class should be 1\n");

   	memcpy(pDomainAddr, buffer+116, 100);
    // for (int i=16;i<216;i++)
    //     cout << buffer[i] << endl;

	return 0;
}


int main(int argc, char const *argv[])
{
	int sockfd;
	ushort TransID = 16;
	ushort portno = 8080;
	char DomainName[] = "video.cse.umich.edu";
	char DNSIp[] = "10.0.0.3";
	char DomainAddr[256] = {0};

    // sockfd  = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockfd  = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
		error("ERROR opening socket");
	SendDndQueryPack(&sockfd, TransID, DomainName, DNSIp, portno);
	RecvDnsPack(&sockfd, TransID, DomainAddr);

    close(sockfd);

	cout << "DomainAddr is: " << DomainAddr << endl;


	return 0;
}