# include <iostream>
# include <fstream>

# include <stdio.h>
# include <string.h>
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
    DNSHeader queryHeader;
    DNSQuestion queryQuestion;
    DNSHeader answerHeader;
    DNSRecord answerRecord;

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
    for (;;)
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

        cout << sizeof(queryHeader) << endl;

        // get DNS header
        memset(buffer, 0, MAXLINE);
        n_recv = recv(newsockfd, 
            (char *)buffer, 
            DNSHeader_size, 
            0);
        queryHeader = DNSHeader::decode(string(buffer));

        // Decoding Header
        //check the AA flag
        if(queryHeader.AA != 0x0)
        {
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

        cout << "DNSQuestion_size :" << DNSQuestion_size <<endl;

        // get DNS question
        memset(buffer, 0, MAXLINE);
        n_recv = recv(newsockfd,
            (char *)buffer,
            DNSQuestion_size,
            0);
        if (n_recv<0)
            error("ERROR reading from socket");
        queryQuestion = DNSQuestion::decode(string(buffer));


        // Seach for corresponding ip address
        if (!strcmp(queryQuestion.QNAME, domainName))
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
        memset(&answerHeader,0, sizeof(answerHeader));
        answerHeader.ID = queryHeader.ID;  // ID
        answerHeader.QR = 0x0;
        answerHeader.AA = 0x1;
        answerHeader.RA = 0x0;
        answerHeader.RD = 0x0;
        answerHeader.Z = 0x0;  
        answerHeader.QDCOUNT = htons(0x1);                                                                       //domain name will be asked per DNS package.
        answerHeader.ANCOUNT = htons(0x1);
        answerHeader.NSCOUNT = htons(0x0);
        answerHeader.ARCOUNT = htons(0X0);

        // Encoding package record
        memset(&answerRecord, 0, sizeof(answerRecord));
        memcpy(answerRecord.NAME, queryQuestion.QNAME, 100);
        answerRecord.TYPE = htons(0x1);
        answerRecord.CLASS = htons(0x1);
        answerRecord.TTL = htons(0x0);
        answerRecord.RDLENGTH = htons(sizeof(answerHeader)+sizeof(answerRecord));
        memcpy(answerRecord.RDATA, rData, 100); 

        // send DNS packet
        string sAnswerHeader = DNSHeader::encode(answerHeader);
        string sAnswerRecord = DNSRecord::encode(answerRecord);
        int DNSAHeader_size = htonl(sAnswerHeader.length());
        int DNSARecord_size = htonl(sAnswerRecord.length());
        int nSent = 0;

        cout << ntohl(DNSAHeader_size) << " " << ntohl(DNSARecord_size)<<endl;   

        nSent = send(newsockfd,
            (char *)&DNSAHeader_size,
            sizeof(DNSAHeader_size),
            0);
        memset(buffer, 0, MAXLINE);
        memcpy(buffer, sAnswerHeader.c_str(), ntohl(DNSAHeader_size));
        nSent = send(newsockfd, 
            (char *)buffer,
            ntohl(DNSAHeader_size),  
            0); 

        nSent = send(newsockfd,
            (char *)&DNSARecord_size,
            sizeof(DNSARecord_size),
            0);
        memset(buffer, 0, MAXLINE);
        memcpy(buffer, sAnswerRecord.c_str(), ntohl(DNSARecord_size));
        nSent = send(newsockfd,
            (char *)buffer,
            ntohl(DNSARecord_size),
            0);
        cout << nSent << endl;
        // logging
        log.open(log_path, ios::app);
        log << srcIPaddr << " " << qDomainName << " " << rData << "\n";
        log.close();
        
        close(newsockfd);
    }
    records.close();
    close(sockfd);

    return 0; 
} 