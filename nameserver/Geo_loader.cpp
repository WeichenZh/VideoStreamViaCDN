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

# include "DNSHeader.h"
# include "DNSQuestion.h"
# include "DNSRecord.h"
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
    if(!log)
        error("Error: no log file!\n");
    // ifstream records;

    // records.open(serversRecord);
    // if(!records)
    //     error("Error: DNS server doesn\'t have record file.\n");
    // if (records.get() == EOF)
    //     error("Error: DNS server doesn\'t have any records.\n");

    // records.clear();
    // records.seekg(0, ios::beg);

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
    for(int k=0;k<5;k++)
    {
        int newsockfd = accept(sockfd, (struct sockaddr *)&cliaddr, &len);
        if (newsockfd < 0)
            error("ERROR on accept");

        n_recv = recv(newsockfd, (char *)buffer, MAXLINE,  0); 
        if (n_recv<0)
            error("ERROR reading from socket");

        // Decoding query package
        BYTE *pQueryPackage = (BYTE *)buffer;
        const char *domainName = "video.cse.umich.edu";
        char qDomainName[100] = {0};
        char rData[100] = {0};
        char rCode = 0;

        // Confirm that the received buffer size is larger than DNS header
        if (n_recv <= sizeof(DNSHeader))
            error("Error: the size of DNS package should be larger than header\n");

        DNSHeader *pRecvHeader = (DNSHeader *)malloc(sizeof(DNSHeader));
        if(!pRecvHeader)
            error("Error: no memory available for DNSHeader\n");

        DNSQuestion *pRecvQuestion = (DNSQuestion *)malloc(sizeof(DNSQuestion));
        if(!pRecvQuestion)
        {
            free(pRecvHeader);
            pRecvHeader = NULL;
            error("Error: no memory available for DNSQuestion\n");
        }

        memcpy(pRecvHeader, pQueryPackage, sizeof(DNSHeader));
        memcpy(pRecvQuestion, pQueryPackage+sizeof(DNSHeader), sizeof(DNSQuestion));

        // Decoding Header
        //check the AA flag
        if(pRecvHeader->AA != 0x0)
        {
            free(pRecvHeader);
            free(pRecvQuestion);
            pRecvHeader = NULL;
            pRecvQuestion = NULL;
            error("Error: received package is not query package\n");
        }
        //TransID = ntohs(pRecvHeader->ID);

        // Decoding question
        /******************************************************/
        /* TUDO: should I return error if QTYPE or QCLASS is not equal to 1? */
        /******************************************************/

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
        //cout << "qDomainName = " << qDomainName << endl;

        // Seach for corresponding ip address
        if (!strcmp(qDomainName, domainName))
        {
            rCode = 0x0;
            strcpy(srcIPaddr, inet_ntoa(cliaddr.sin_addr));
            nearest_server_addr(serversRecord, srcIPaddr, rData);
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

        // Encoding Answering package
        BYTE *pApackage = (BYTE *)malloc(sizeof(DNSHeader) + sizeof(DNSRecord));
        if (!pApackage)
        {
            free(pAHeader);
            free(pARecord);
            error("Error: no memory available for Answer package\n");
        }
        memset(pApackage, 0, sizeof(DNSHeader)+sizeof(DNSRecord));
        memcpy(pApackage, pAHeader, sizeof(DNSHeader));
        memcpy(pApackage+sizeof(DNSHeader), pARecord, sizeof(DNSRecord));

        send(newsockfd, 
            (const char *)pApackage,
            sizeof(DNSHeader)+sizeof(DNSRecord),  
            0); 
        
        // logging
        log << srcIPaddr << " " << qDomainName << " " << rData << "\n";

        // clean the resource
        free(pRecvHeader);
        free(pRecvQuestion);
        free(pAHeader);
        free(pARecord);
        free(pApackage);
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

    int edge[20][20], dst[20], book[20];
    int serverIDs[20], clientIDs[20];
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
    		nNodes = ushort(record.c_str()[11] - 48); 
    	}
    	else if(!strncasecmp(record.c_str(), "NUM_LINKS", 9))
    	{
    		// cout << record <<endl;
    		nLinks = ushort(record.c_str()[11] - 48);
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

    			edge[atoi(parse_str[0])][atoi(parse_str[1])] = atoi(parse_str[2]);
    			edge[atoi(parse_str[1])][atoi(parse_str[0])] = atoi(parse_str[2]) ;
    		}
    	}
    }

	dijkstra(IPtoID[object_ip], edge, dst, book, nNodes, nLinks);

	int serverID = distance(dst, min_element(&dst[serverIDs[0]], &dst[serverIDs[0]]+num_server));
	string serverIP = IDtoIP[serverID];
	if (!serverIP.size())
		cout << "Error: invalid address." <<endl;
    strcpy(nearest_server, serverIP.c_str());

    records.close();
	return 0;
}

