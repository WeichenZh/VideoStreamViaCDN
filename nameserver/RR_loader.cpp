# include <stdio.h>
# include <string.h>
# include <iostream>
# include <fstream>
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
# include "error_msg.h"

#define MAXLINE 512 

using namespace std;
typedef uint8_t BYTE;

int RR_loader(int argc, char const *argv[]) 
{
    const char *serversRecord = argv[3];
    const char *log_path = argv[4];
    ifstream records;
    ofstream log;

    records.open(serversRecord);
    if(!records)
        error("Error: DNS server doesn\'t have record file.\n");
    if (records.get() == EOF)
        error("Error: DNS server doesn\'t have any records.\n");
    records.clear();
    records.seekg(0, ios::beg);

    log.open(log_path, ios::trunc);
    if(!log)
        error("Error: no log file!\n");
    log.close();

    /* Decoding query package */
    // BYTE *pQueryPackage = (BYTE *)buffer;
    const char *domainName = "video.cse.umich.edu";
    char qDomainName[100] = {0};
    char rData[100] = {0};
    char rCode = 0;

    /**** socket part ****/
    int sockfd, n_recv, portno;
    const int optval = 1; 
    char buffer[MAXLINE]; 
    char srcIPaddr[20];
    struct sockaddr_in servaddr, cliaddr; 
    socklen_t len = sizeof(cliaddr);

    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0)
        error("setsockopt(SO_REUSEADDR) failed");
      
    // Filling server information 
    portno = atoi(argv[2]);
    servaddr.sin_family = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(portno); 
      
    // Bind the socket with the server address 
    if ( bind(sockfd, (const struct sockaddr *)&servaddr,  
            sizeof(servaddr)) < 0 ) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    listen(sockfd, 5);
    for (int k=0;;k++)
    {
        int newsockfd = accept(sockfd, (struct sockaddr *)&cliaddr, &len);
        if (newsockfd < 0)
            error("ERROR on accept");
        //get client ip address
        strcpy(srcIPaddr, inet_ntoa(cliaddr.sin_addr));

        // get DNS header size
        int DNSHeader_size;
        n_recv = recv(newsockfd, 
            (char *)buffer, 
            sizeof(DNSHeader_size),  
            0); 
        if (n_recv<0)
            error("ERROR reading from socket");
        memcpy(&DNSHeader_size, (BYTE *)buffer, sizeof(DNSHeader_size));
        DNSHeader_size = ntohl(DNSHeader_size);
        if (DNSHeader_size <= 0)
            error("Error: DNSHeader size must be greater than 0.\n");

        // get DNS header
        memset(buffer, 0, MAXLINE);
        n_recv = recv(newsockfd, 
            (char *)buffer, 
            DNSHeader_size, 
            0);
        DNSHeader *pRecvHeader = (DNSHeader *)malloc(DNSHeader_size);
        if(!pRecvHeader)
            error("Error: no memory available for DNSHeader\n");
        memset(pRecvHeader, 0, DNSHeader_size);
        memcpy(pRecvHeader, buffer, DNSHeader_size);

        // Decoding Header
        //check the AA flag
        if(pRecvHeader->AA != 0x0)
        {
            free(pRecvHeader);
            pRecvHeader = NULL;
            error("Error: received package is not query package\n");
        }

        // Decoding question
        /******************************************************/
        /* TUDO: should I return error if QTYPE or QCLASS is not equal to 1? */
        /******************************************************/


        // get DNS question size
        int DNSQuestion_size;
        memset(buffer, 0, MAXLINE);
        n_recv = recv(newsockfd, 
            (char *)buffer, 
            sizeof(DNSQuestion_size), 
            0);
        if (n_recv<0)
            error("ERROR reading from socket");
        memcpy(&DNSQuestion_size, (BYTE *)buffer, sizeof(DNSQuestion_size));
        DNSQuestion_size = ntohl(DNSQuestion_size);
        if (DNSQuestion_size < 0)
            error("Error: DNS question size must be greater than 0.\n");

        // get DNS question
        memset(buffer, 0, MAXLINE);
        n_recv = recv(newsockfd,
            (char *)buffer,
            DNSQuestion_size,
            0);
        if (n_recv<0)
            error("ERROR reading from socket");

        DNSQuestion *pRecvQuestion = (DNSQuestion *)malloc(DNSQuestion_size);
        if(!pRecvQuestion)
        {
            free(pRecvHeader);
            pRecvHeader = NULL;
            error("Error: no memory available for DNSQuestion\n");
        }
        memset(pRecvQuestion, 0, DNSQuestion_size);
        memcpy(pRecvQuestion, (BYTE *)buffer, DNSQuestion_size);

        // Convert 3www6google3com to www.google.com
        unsigned int pos = 0;
        unsigned int seg_len = 0;
        for (;seg_len = pRecvQuestion->QNAME[pos];)
        {
            memcpy(qDomainName+pos, pRecvQuestion->QNAME+pos+1, seg_len);
            qDomainName[pos+seg_len] = '.';
            pos += seg_len +1;
        }
        if (qDomainName[pos-1]=='.')
            qDomainName[pos-1] = 0;
        // cout << "qDomainName = " << qDomainName << endl;

        // Seach for corresponding ip address
        if (!strcmp(qDomainName, domainName))
        {
            rCode = 0x0;
            string record;
            if (!getline(records, record))
            {
                records.clear();
                records.seekg(0, ios::beg);
                getline(records, record);
            }
            memcpy(rData, record.c_str(), 100);
        }
        else
        {
            rCode = 0x3;
            memset(rData, 0, 100);
        }

        // Encoding Answer package
        // Encoding package Header
        DNSHeader *pAHeader = (DNSHeader *)malloc(sizeof(DNSHeader));
        if (!pAHeader)
            error("Error: no memory available for Answer package header\n");
        memset(pAHeader, 0, sizeof(DNSHeader));
        pAHeader->ID = pRecvHeader->ID;  // ID
        pAHeader->QR = 0x0;
        pAHeader->AA = 0x1;
        pAHeader->RA = 0x0;
        pAHeader->RD = 0x0;
        pAHeader->Z = 0x0;  
        pAHeader->QDCOUNT = htons(0x1);  //I set it to 1 because so far I just assume that only 1 
                                                                            //domain name will be asked per DNS package.
        pAHeader->ANCOUNT = htons(0x1);
        pAHeader->NSCOUNT = htons(0x0);
        pAHeader->ARCOUNT = htons(0X0);

        // Encoding package record
        DNSRecord *pARecord = (DNSRecord *)malloc(sizeof(DNSRecord));
        if (!pARecord)
        {
            free(pAHeader);
            pAHeader=NULL;
            error("Error: no memory available for Answer package record\n");
        }
        memset(pARecord, 0, sizeof(DNSRecord));
        memcpy(pARecord->NAME, pRecvQuestion->QNAME, 100);
        pARecord->TYPE = htons(0x1);
        pARecord->CLASS = htons(0x1);
        pARecord->TTL = htons(0x0);
        pARecord->RDLENGTH = htons(sizeof(DNSHeader)+sizeof(DNSRecord));
        memcpy(pARecord->RDATA, rData, 100); 

        // send DNS packet
        int DNSAHeader_size = htonl(sizeof(DNSHeader));
        int DNSARecord_size = htonl(sizeof(DNSRecord));
        int nSent = 0;

        nSent = send(newsockfd,
            (char *)&DNSAHeader_size,
            sizeof(DNSAHeader_size),
            0);
        nSent = send(newsockfd, 
            (char *)pAHeader,
            ntohl(DNSAHeader_size),  
            0); 
        nSent = send(newsockfd,
            (char *)&DNSARecord_size,
            sizeof(DNSARecord_size),
            0);
        nSent = send(newsockfd,
            (char *)pARecord,
            ntohl(DNSARecord_size),
            0);

        // logging
        log.open(log_path, ios::app);
        log << srcIPaddr << " " << qDomainName << " " << rData << "\n";
        log.close();

        // clean the resource
        free(pRecvHeader);
        free(pRecvQuestion);
        free(pAHeader);
        free(pARecord);
        close(newsockfd);
    }
    records.close();
    close(sockfd);

    return 0; 
} 