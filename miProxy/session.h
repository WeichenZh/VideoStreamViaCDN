#ifndef SESSION_H
#define SESSION_H
#define BUFFERSIZE 1048576
#define BUFFERSIZESMALL 1024
#define IPSIZE 30
#include <vector>
using namespace std;

class Proxy
{
    int port, master_socket, cdn_socket, new_socket, valread;
    vector<int> tps;
    double alpha, tp_estimated=-1.0;
    char buffer[BUFFERSIZE] = {0};
    char serverIp[IPSIZE], log_path[BUFFERSIZESMALL];
    //FOR_LOG_FILE
    double duration_curr=0.0, tp_curr=0.0;
    char cdn_addr[IPSIZE]={0}, chunk_name[IPSIZE]={0};

    void add_client(int new_socket);
    void rearrange_GET();
    void update_tp(int numbits, double duration_ns);
    void readXML();//TODO
    void write_to_logfile(char const *browser_ip);//TODO
public:
    Proxy(int lp, char const *ho, double ap, char const *lg);
    void run();
    void print() {//DEBUG
        printf("port: %d, serverIp: %s, alpha: %.3f, log_path: log_path %s\n", port, serverIp, alpha, log_path);
    }
};

void get_host_from_DNS(char const *host, int port, char *host_cdn);
  
#endif
