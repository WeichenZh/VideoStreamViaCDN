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

# include <map>
# include <iostream>
# include <fstream>
# include <algorithm>
# include <vector>
# include <typeinfo>

# include "../starter_files/DNSHeader.h"
# include "../starter_files/DNSQuestion.h"
# include "../starter_files/DNSRecord.h"
# include "Dijkstra.h"
# include "Geo_loader.h"
# include "error_msg.h"

# define INF 65535
# define MAXLINE 512
using namespace std;
typedef uint8_t BYTE;


// int dijkstra(int srcpID, int (*e)[20], int *dis, int *book, int nNodes, int nLinks);
// int nearest_server_addr(const char *, char *, char *);

int Geo_loader(int argc, char const *argv[])
{
    const char *serversRecord = argv[3];
    const char *log_path = argv[4];

    ofstream log;
    log.open(log_path, ios::trunc);
    // if(!log)
    //     error("Error: no log file!\n");
    log.close();

    /* Decoding query package config */
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
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0)
        error("setsockopt(SO_REUSEADDR) failed");

    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
      
    // Filling server information 
    portno = atoi(argv[2]);
    servaddr.sin_family    = AF_INET; // IPv4 
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
    for(;;)
    {
        int newsockfd = accept(sockfd, (struct sockaddr *)&cliaddr, &len);
        if (newsockfd < 0)
            error("ERROR on accept");

        //get client ip address
        strcpy(srcIPaddr, inet_ntoa(cliaddr.sin_addr));
        // receive size of DNS header
        int DNSHeader_size;
        n_recv = recv(newsockfd, (char *)buffer, sizeof(DNSHeader_size),  0); 
        if (n_recv<0)
            error("ERROR reading from socket");

        memcpy(&DNSHeader_size, (BYTE *)buffer, sizeof(DNSHeader_size));
        DNSHeader_size = ntohl(DNSHeader_size);


        // receive DNS header
        memset(buffer, 0, MAXLINE);
        n_recv = recv(newsockfd, (char *)buffer, DNSHeader_size, 0);
        if (n_recv < 0)
            error("ERROR reading from socket");
        queryHeader = DNSHeader::decode(string(buffer));

        // Decoding Header
        // check the AA flag
        if(queryHeader.AA != 0x0)
        {
            error("Error: received package is not query package\n");
        }

        // Decoding question
        /******************************************************/
        /* TUDO: should I return error if QTYPE or QCLASS is not equal to 1? */
        /******************************************************/
        
        // receive DNS Question size
        int DNSQuestion_size;
        memset(buffer, 0, MAXLINE);
        n_recv = recv(newsockfd, (char *)buffer, sizeof(DNSQuestion_size),  0); 
        if (n_recv<0)
            error("ERROR reading from socket");
        memcpy(&DNSQuestion_size, (BYTE *)buffer, sizeof(DNSQuestion_size));
        DNSQuestion_size = ntohl(DNSQuestion_size);
        // cout << "DNS Question size: " << DNSQuestion_size << endl;
        if (DNSQuestion_size < 0)
            error("Error: DNS question size must be greater than 0\n");

        // receive DNS Question
        memset(buffer, 0, MAXLINE);
        n_recv = recv(newsockfd, (char *)buffer, DNSQuestion_size, 0);
        if (n_recv<0)
            error("ERROR reading from socket");
        queryQuestion = DNSQuestion::decode(string(buffer));

        // Seach for corresponding ip address
        if (!strcmp(queryQuestion.QNAME, domainName))
        {
            rCode = 0x0;
            nearest_server_addr(serversRecord, srcIPaddr, rData);
        }
        else
        {
            rCode = 0x3;
            memset(rData, 0, 100);
        }

        // Encoding Answer package
        // Encoding package Header
        memset(&answerHeader, 0, sizeof(answerHeader));
        answerHeader.ID = queryHeader.ID;  // ID
        answerHeader.QR = 0x0;
        answerHeader.AA = 0x1;
        answerHeader.RA = 0x0;
        answerHeader.RD = 0x0;
        answerHeader.Z = 0x0;  
        answerHeader.QDCOUNT = htons(0x1);  //I set it to 1 because so far I just assume that only 1                                                                //domain name will be asked per DNS package.
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
        
        // logging
        log.open(log_path, ios::app);
        log << srcIPaddr << " " << qDomainName << " " << rData << "\n";
        log.close();

        close(newsockfd);
    }
    close(sockfd);
    return 0; 
}


int nearest_server_addr(const char *servers, char *query_ip, char *nearest_server)
{   
    string object_ip = string(query_ip);
    ifstream records;
    string record;

    records.open(servers);
    if(!records)
        error("Error: DNS server doesn\'t have record file.\n");
    if (records.get() == EOF)
        error("Error: DNS server doesn\'t have any records.\n");
    records.clear();
    records.seekg(0, ios::beg);

    float edge[20][20], dst[20];
    int serverIDs[20], clientIDs[20], book[20];
    ushort num_server=0, num_client=0, nNodes = 0, nLinks = 0;
    map<string, int> IPtoID;
    map<int, string> IDtoIP;

    // init graph
    // init adjacency table
    for (int i=0;i<20;i++)
        for (int j=0;j<20;j++)
        {
            edge[i][j] = INF;
            if(i==j)
                edge[i][j] = 0;
        }

    while(getline(records, record))
    {
        // cout << record <<endl;
        if(!strncasecmp(record.c_str(), "NUM_NODES", 9))
        {
            nNodes = ushort(atoi((char *)&record[11])); 
        }
        else if(!strncasecmp(record.c_str(), "NUM_LINKS", 9))
        {
            // cout << record <<endl;
            nLinks = ushort(atoi((char *)&record[11])); 
        }
        else
        {
            char token[20];
            char parse_str[3][20];
            strcpy(token, record.c_str());
            char *p = strtok(token, " ");
            for (int i = 0; p && i<3 ;i++)
            {
                strcpy(parse_str[i], p);
                p = strtok(NULL, " ");
            }
            if (!strcmp(parse_str[1], "CLIENT"))
            {
                int ID = atoi(parse_str[0]);
                string hostIP = string(parse_str[2]);
                clientIDs[num_client] = ID;
                IPtoID[hostIP] = ID;
                IDtoIP[ID] = hostIP;
                num_client++;
            }
            else if(!strcmp(parse_str[1], "SERVER"))
            {
                int ID = atoi(parse_str[0]);
                string hostIP = string(parse_str[2]);
                serverIDs[num_server] = ID;
                IPtoID[hostIP] = ID;
                IDtoIP[ID] = hostIP;
                num_server++;
            }
            else if(!strcmp(parse_str[1], "SWITCH"))
                continue;
            else
            {

                edge[atoi(parse_str[0])][atoi(parse_str[1])] = atof(parse_str[2]);
                edge[atoi(parse_str[1])][atoi(parse_str[0])] = atof(parse_str[2]);
            }
        }
    }

    dijkstra(IPtoID[object_ip], edge, dst, book, nNodes, nLinks);

    // find the closest server IP
    float min_dis = 100000.0;
    int clst_serverID=-1;
    for(int i=0;i<num_server;i++)
    {
        if(dst[serverIDs[i]] < min_dis)
        {
            min_dis = dst[serverIDs[i]];
            clst_serverID = serverIDs[i];
        }
    }
    // cout << " closest server ID: ";
    // cout << clst_serverID << endl;
    string serverIP = IDtoIP[clst_serverID];
    if (!serverIP.size())
        cout << "Error: invalid address." <<endl;
    strcpy(nearest_server, serverIP.c_str());

    records.close();
    return 0;
}