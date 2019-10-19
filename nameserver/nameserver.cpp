# include <iostream>
# include <cstdlib>
# include <cstdio>
# include <string.h>
# include "RR_loader.h"
# include "Geo_loader.h"
# include "error_msg.h"

int main(int argc, char const *argv[])
{
    if (argc != 5) {
       fprintf(stderr,"usage %s [--geo|--rr] <port> <servers> <log>\n", argv[0]);
       error("Error: missing or extra arguments");
    }
    if(!strcmp(argv[1],"--rr"))
    	RR_loader(argc, argv);
    else if(!strcmp(argv[1], "--geo"))
    	Geo_loader(argc, argv);
    else
        error("Error:invalid argument of balance loader.");
	return 0;
}
