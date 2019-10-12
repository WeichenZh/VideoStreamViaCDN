// Server side C/C++ program to demonstrate Socket programming 
#include <unistd.h>
#include <string.h>
#include <stdio.h> 
#include <stdlib.h>
#include <iostream>
#include "session.h"
 
using namespace std;

bool same(char const * c, char const * tar){
	return strcmp(c, tar)==0;
}

int err(int type = 0){
	cout << ("Error: missing or extra arguments") << endl;
	exit(EXIT_FAILURE);
}


int main(int argc, char const *argv[]){
	if(argc>1){
		int listen_port;
		double alpha;
		char const *log_path;
		char host[40];
		if(same(argv[1],"--nodns")){ //server
			if(argc != 6) err();
			listen_port = atoi(argv[2]);
			strcpy(host, argv[3]);
			log_path = argv[5];
			alpha = atof(argv[4]);
		}
		else if(same(argv[1],"--dns")){ //client
			if(argc != 7) err();
			
			listen_port  = atoi(argv[2]);
			log_path = argv[6];
			alpha = atof(argv[5]);

			get_host_from_DNS(argv[3], atoi(argv[4]), host);
		}
		else err();

		Proxy proxy(listen_port, host, alpha, log_path);
		proxy.run();
	}
	printf("FIN\n");
	return 0;
}
