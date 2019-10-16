#ifndef DNS_SENDER_H
#define DNS_SENDER_H

int SendDndQueryPack(int *psockfd, ushort TransID, char *domainName, char *DNSaddr, ushort portno);
int RecvDnsPack(int *psockfd, ushort TransID, char *pDomainAddr);
  
#endif
