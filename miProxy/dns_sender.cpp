# include <stdio.h>
# include <time.h>
# include <string.h>
# include <iostream>
# include <stdlib.h>
# include <stdint.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <unistd.h>
# include "DNSHeader.h"
# include "DNSQuestion.h"
# include "DNSRecord.h"

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

    // Encoding domain name
    unsigned int domain_len = strlen(domainName);
    unsigned int QdomainName_len = domain_len + 2;
    BYTE *QdomainName = (BYTE *)malloc(domain_len+2);
    if (!QdomainName)
    {
        error("Error: no space for domian name.\n");
    }
    memset(QdomainName, 0, domain_len);
    //convert domian name to DNS format. eg: www.google.com to 3www6google3com
    for (unsigned int i =0, npos=0 ;i < domain_len+1; i++)
    {
        if (domainName[i] == '.' || i==domain_len)
        {
            QdomainName[npos] = i-npos;
            if (QdomainName[npos])
            {
                memcpy(QdomainName+npos+1, domainName+npos, i-npos);
            }
            npos = i+1;
        }
    }

    // Encoding  Header
    DNSHeader *PDNSHeader = (DNSHeader*)malloc(sizeof(DNSHeader) );
    if (!PDNSHeader)
    {
        free(QdomainName);
        QdomainName = NULL;
        error("Error:can not allocate memory for DNS header\n");
    }
    memset(PDNSHeader, 0, sizeof(DNSHeader) );
     // Encoding Header
    PDNSHeader->ID = htons(TransID);  // ID
    PDNSHeader->QR = 0x0;
    PDNSHeader->AA = 0x0;
    PDNSHeader->RA = 0x0;
    PDNSHeader->RD = 0x0;
    PDNSHeader->Z = 0x0;  
    PDNSHeader->QDCOUNT = htons(0x1);  //I set it to 1 because so far I just assume that only 1 
                                                                        //domain name will be asked per DNS package.
    PDNSHeader->ANCOUNT = htons(0x0);
    PDNSHeader->NSCOUNT = htons(0x0);
    PDNSHeader->ARCOUNT = htons(0X0);


    // Encoding Question:  name + type + class
    DNSQuestion *PDNSQuestion = (DNSQuestion *)malloc(sizeof(DNSQuestion));
    if (!PDNSQuestion)
    {
        free(QdomainName);
        free(PDNSHeader);
        QdomainName = NULL;
        PDNSHeader = NULL;
        error("Error:can not allocate memory for DNS question\n");
    }
    memset(PDNSQuestion, 0, sizeof(DNSQuestion) );
    memcpy(PDNSQuestion -> QNAME, QdomainName, QdomainName_len);
    PDNSQuestion -> QTYPE = htons(0x1);
    PDNSQuestion -> QCLASS = htons(0x1); 

    //Encoding Header+Question
    BYTE *PDNSPackage = (BYTE *)malloc(sizeof(DNSHeader) + sizeof(DNSQuestion));
    if (!PDNSPackage)
    {
        free(QdomainName);
        free(PDNSHeader);
        free(PDNSQuestion);
        QdomainName = NULL;
        PDNSHeader = NULL;
        PDNSQuestion = NULL;
        error("Error:can not allocate memory for DNS package\n");
    }
    memset(PDNSPackage, 0, sizeof(DNSHeader)+sizeof(DNSQuestion));
    memcpy(PDNSPackage, PDNSHeader, sizeof(DNSHeader));
    memcpy(PDNSPackage+sizeof(DNSHeader), PDNSQuestion, sizeof(DNSQuestion));

    // prepare for sending
    sockaddr_in dnsServAddr;
    bzero((char *) &dnsServAddr, sizeof(dnsServAddr));
    dnsServAddr.sin_family = AF_INET;
    dnsServAddr.sin_port = htons(portno);  // DNS server port default is 53
    dnsServAddr.sin_addr.s_addr = inet_addr(DNSaddr);

    if (connect(*psockfd, (struct sockaddr *)&dnsServAddr,sizeof(dnsServAddr)) < 0)
        error("ERROR connecting");

    int nSent = send(*psockfd,
        (char*)PDNSPackage,
        sizeof(DNSHeader) + sizeof(DNSQuestion),
        0);

    if (nSent < 0)
    {
        free(QdomainName);
        free(PDNSHeader);
        free(PDNSQuestion);
        free(PDNSPackage);
        error("DNS package send fail!\n");
    }

    // clean up the resources      
    if(PDNSPackage)
        free(PDNSPackage); PDNSPackage=NULL;
    if(PDNSHeader)
        free(PDNSHeader); PDNSHeader=NULL;
    if(PDNSQuestion)
        free(PDNSQuestion); PDNSQuestion=NULL;
    if(QdomainName)
        free(QdomainName); QdomainName=NULL;

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

    // int n_recv = recvfrom(*psockfd,
    //  buffer,
    //  MAXLINE,
    //  0,
    //  (sockaddr *)&servAddr,
    //  &len);
    int n_recv = recv(*psockfd,
        buffer,
        MAXLINE,
        0);

    if (n_recv < 0)
        error("Error reading from socket\n");

    // Decoding Answer package
    if (n_recv < sizeof(DNSHeader))
        error("Error: invalid package length\n");
    // Decoding Answer Header
    DNSHeader *pAHeader = (DNSHeader *)malloc(sizeof(DNSHeader));
    if (!pAHeader)
        error("Error: no memory available for parsing Answer header\n");
    memset(pAHeader, 0, sizeof(DNSHeader));
    memcpy(pAHeader, buffer, sizeof(DNSHeader));

    if (pAHeader->ID != htons(TransID))
        {
            free(pAHeader); 
            pAHeader = NULL;
            error("Error: Query package ID is not consistent with Answer package ID\n");
        }
    if (pAHeader->AA != 0x1)
    {
        free(pAHeader);
        pAHeader = NULL;
        error("Error: the package is not Answer package\n");
    }
    if (pAHeader -> RCODE != 0x0)
    {
        if (pAHeader -> RCODE == 0x3)
        {
            cout << "The IP address of querying server doesn\'t exist" <<endl;
            free(pAHeader);
            pAHeader = NULL;
            return 0;
        }
    }
    // Decoding Answer Record
    DNSRecord *pARecord = (DNSRecord *)malloc(sizeof(DNSRecord));
    if (!pARecord)
    {
        free(pAHeader);
        pAHeader = NULL;
        error("Error: no memory available for parsing the Answer package Record\n");
    }
    memset(pARecord, 0, sizeof(DNSRecord));
    memcpy(pARecord, buffer+sizeof(DNSHeader), sizeof(DNSRecord));

    if (pARecord -> TYPE != htons(0x1))
    {
        free(pAHeader);
        free(pARecord);
        pAHeader =NULL;
        pARecord = NULL;
        error("Error: Record type should be 1\n");
    }
    if (pARecord -> CLASS != htons(0x1))
    {
        free(pAHeader);
        free(pARecord);
        pAHeader =NULL;
        pARecord = NULL;
        error("Error: Record class should be 1\n");
    }

    memcpy(pDomainAddr, pARecord->RDATA, 100);

    // clean the resourse
    free(pAHeader);
    free(pARecord);
    pAHeader = NULL;
    pARecord = NULL;

    return 0;
}
