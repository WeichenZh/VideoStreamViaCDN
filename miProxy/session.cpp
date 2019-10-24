#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <iostream>
#include <fstream>
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h> 
#include "session.h"
#include "dns_sender.h"
#include <ctime>
#include <vector>
#include <time.h>
#include <chrono>
#include <array>
#include <map>
#include <algorithm>
//parameters
#define MAXCLIENT 100
#define MAXURL 128
#define PORT 80
//#define BUFFERSIZE 65536

using namespace std;

class Client
{
public:
    double tp_estimated;
    vector<int> tps;
    int id;
    Client(int idx){
        id = idx;
        tp_estimated=-1.0;
    }
    int get_tp(){
        if (tps.size()==0) return 0;
        int max_idx;
        for (int i = 1; i < tps.size(); ++i){
            max_idx = i;
            if (tp_estimated < (tps[i]*1.5)){
                max_idx -= 1;
                break;
            }
        }
        return tps[max_idx];
    }
};

int err(char const *error){
    printf("Error: %s\n", error);
    exit(EXIT_FAILURE);
}

class Timer
{
public:
    Timer() {restart();}
    void restart() {m_StartTime = chrono::system_clock::now();}
    double duration_ns() {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(chrono::system_clock::now() - m_StartTime).count();
    }
private:
    chrono::time_point<chrono::system_clock> m_StartTime;
};

int get_master_socket(struct sockaddr_in *address, int port){
    int master_socket, opt = 1;  
    // Creating socket file descriptor 
    if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        err("socket failed");
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
        &opt, sizeof(opt)))
        err("setsockopt"); 
    address->sin_family = AF_INET; 
    address->sin_addr.s_addr = INADDR_ANY; 
    address->sin_port = htons(port); 
    // Forcefully attaching socket to the port
    if (bind(master_socket, (struct sockaddr *)address, sizeof(*address))<0)
        err("bind failed");
    if (listen(master_socket, 3) < 0) 
        err("listen"); 
    return master_socket;
}

Proxy::Proxy(int lp, char const *ho, double ap, char const *lg){
    port     = lp;
    strcpy(serverIp, ho);
    alpha    = ap;
    strcpy(log_path, lg);
}

int connect_CDN(char const *host, char *cdn_addr)
{
    int sock; 
    struct sockaddr_in serv_addr; 
    
    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) err("Socket creation error");
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 
    if(inet_pton(AF_INET, host, &serv_addr.sin_addr)<=0) err("Invalid address/ Address not supported");
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) err("Connection Failed");
    strcpy(cdn_addr, inet_ntoa(serv_addr.sin_addr));
    return sock;
}

int recv_http(int client_socket, char *buffer){
    int ctr=recv(client_socket, buffer, 1000, 0);
    if (ctr!=-1){
        buffer[ctr] = '\0';
        string buff(buffer);
        ssize_t pos = buff.find("Content-Length");
        if (pos != string::npos){
            const int len_body = atoi(buff.substr(pos+15, buff.find(pos,'\n')).c_str()) - ctr + (buff.find("\r\n\r\n")+4);
            if ((ctr-(buff.find("\r\n\r\n")+4))<len_body){
                ctr += recv(client_socket, buffer+ctr, len_body, MSG_WAITALL);
                buffer[ctr] = '\0';
            }
        }
        buffer[ctr] = '\0';
    }
    else buffer[0] = '\0';
    return ctr;
}

void Proxy::readXML(){
    //TODO--message will be in buffer
    //e.g. you can directly use variable "buffer"
    string buff(buffer);
    ssize_t pos = buff.find("bitrate");
    while (pos != string::npos){
        pos += 9;
        ssize_t pos_end = buff.find("\n",pos);
        tps.push_back(stoi(buff.substr(pos, pos_end-pos-1)));
        pos = buff.find("bitrate", pos);
    }
    sort(tps.begin(), tps.begin()+tps.size());
}

void Proxy::write_to_logfile(char const* browser_ip){
    //<browser-ip> <chunkname> <server-ip> <duration> <tput> <avg-tput> <bitrate>
    string log(browser_ip), sep(" "), strBuff(chunk_name);//browser-ip
    log += sep + strBuff;//chunkname
    log += sep + cdn_addr;//server-ip
    log += sep + to_string(duration_curr/1000.0);//duration_curr
    log += sep + to_string(tp_curr);//tput
    log += sep + to_string(tp_estimated);//avg-tput
    log += sep + strBuff.substr(0, strBuff.find("Seg")) ;//bitrate
    ofstream out(log_path,ios::app);
    out<<log<<endl;
    out.close();
}

void Proxy::update_tp(int numbits, double duration_ms){
    //numbits: # of bits(not Bite)
    //duration_ms: RTT in ms
    duration_curr = duration_ms;///2;//one-way delay(ms)
    tp_curr = numbits/duration_curr;//Kbps
    tp_estimated = (tp_estimated<0)? tp_curr: (alpha*tp_curr+(1-alpha)*tp_estimated);//exponential update
}

void Proxy::rearrange_GET(){
    char chrBuff[BUFFERSIZESMALL]={0}, chrtp[10]={0};
    char *find_Seg = strstr(buffer,"Seg");
    if (find_Seg != NULL){
        strncpy(chrBuff, buffer, 9);//GET
        int max_idx;
        for (int i = 1; i < tps.size(); ++i){
            max_idx = i;
            if (tp_estimated < (tps[i]*1.5)){
                max_idx -= 1;
                break;
            }
        }
        strcpy(chrBuff+strlen(chrBuff), to_string(tps[max_idx]).c_str());
        strcpy(chrBuff+strlen(chrBuff), find_Seg);
        strcpy(buffer, chrBuff);

        string chunk_buff(chrBuff);
        ssize_t pos_seg = chunk_buff.find("Seg");
        while (chunk_buff[pos_seg]!='/') pos_seg -= 1;
        chunk_buff = chunk_buff.substr(pos_seg+1, chunk_buff.find("HTTP")-pos_seg-2);
        strcpy(chunk_name, chunk_buff.c_str());
        //printf("%.3f|%d|%s\n", tp_estimated/1.5, tps[max_idx], chunk_name);
    }
    else if (strstr(buffer,".f4m") != NULL){
        find_Seg = strstr(buffer,".f4m");
        strcpy(chrBuff, find_Seg);
        strcpy(find_Seg, "_nolist");
        strcpy(find_Seg+7, chrBuff);
    }
}

void printHeader(const char *head, char *buffer){
    char strBuff[300]={0};
    strncpy(strBuff, buffer, 300);
    printf("\n-------------%s-------------\n%s\n", head, strBuff);
}

void Proxy::run(){
    struct sockaddr_in address_server, address_client; 
    master_socket = get_master_socket(&address_server, port);
    int addrlen = sizeof(address_server), valread;
    array<Client*,MAXCLIENT> client_sockets;
    client_sockets.fill(NULL);

    cdn_socket = connect_CDN(serverIp, cdn_addr);
    ofstream fileout(log_path,ios::trunc);

    Timer tmr;
    fd_set rfds;
    while(true){
        FD_ZERO(&rfds);
        FD_SET(master_socket, &rfds);
        for (auto& client_socket: client_sockets){
            if (client_socket != NULL) FD_SET(client_socket->id, &rfds);
        }

        if (select(FD_SETSIZE, &rfds, NULL, NULL, NULL) < 0) err("select error");

        if (FD_ISSET(master_socket, &rfds)){
            //printf("\n---New Host---\n");
            new_socket = accept(master_socket, (struct sockaddr *)&address_client, 
                                (socklen_t*)&addrlen);
            if (new_socket < 0) err("accept");
            //printf("Message: %s\n", buffer);
            //printf("Socket fd is %d, IP is: %s, port: %d\n", 
            //       new_socket, inet_ntoa(address_client.sin_addr), ntohs(address_client.sin_port));
            for (auto& client_socket: client_sockets){
                if (client_socket==NULL){
                    client_socket = new Client(new_socket);
                    break;
                }
            }
        }
        for (auto& client: client_sockets){
            if (client == NULL) continue;
            int client_socket = client->id;
            if (client_socket!=0 && FD_ISSET(client_socket, &rfds)){
                getpeername(client_socket, (struct sockaddr *)&address_client, 
                            (socklen_t*)&addrlen);
                valread = recv_http(client_socket, buffer);
                tmr.restart();
                if (client_socket==cdn_socket) printf("Received Message FROM cdn_socket\n");
                
                if (valread == 0){//end
                    close(client_socket);
                    delete client;
                    client = NULL;
                }
                else{
                    tp_estimated = client->tp_estimated;
                    bool is_seg = (strstr(buffer,"Seg") != NULL);

                    if ((strstr(buffer,".f4m") != NULL) && (tps.size() == 0)){
                        char chrBuff[BUFFERSIZESMALL]={0};
                        strcpy(chrBuff, buffer);
                        send(cdn_socket, buffer, strlen(buffer), 0);
                        valread = recv_http(cdn_socket, buffer);
                        readXML();
                        strcpy(buffer, chrBuff);
                    }

                    rearrange_GET();
                    send(cdn_socket, buffer, strlen(buffer), 0);//valread will changed

                    valread = recv_http(cdn_socket, buffer);//recv from webServer

                    if (is_seg){
                      //  ofstream fileout(log_path,ios::trunc);
                        update_tp(valread*8, tmr.duration_ns()/1000000.0);//Bite to bit
                        //printf("size: %d b, t: %.3f ms, tp: %.3f Kbps, tpc: %.3f Kbps, tps_sz: %d\n", valread*8, duration_curr, valread*8/duration_curr, tp_curr, 0);
                        write_to_logfile(inet_ntoa(address_client.sin_addr));
                    }
                    send(client_socket, buffer, valread, 0);
                    client->tp_estimated = tp_estimated;
                }
            }
        }
    }
}

void get_host_from_DNS(char const *host, int port, char *host_cdn)
{
    int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
    char buffer[BUFFERSIZESMALL]={0}, host_buff[BUFFERSIZESMALL];
    ushort TransID = 1000;
    char *DomainName = "video.cse.umich.edu";

    strcpy(host_buff, host);
    
    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) err("Socket creation error");

    SendDndQueryPack(&sock, TransID, DomainName, host_buff, port);
    RecvDnsPack(&sock, TransID, buffer);

    cout << "DomainAddr is: " << buffer << endl;

    strcpy(host_cdn, buffer);

    close(sock);
}