#include<stdio.h>

#define INF 65535

int dijkstra(int srcpID, int (*e)[20], int *dis, int *book, int nNodes, int nLinks){
	int min, i, j, v, u;
	int n = nNodes;
	int m = nLinks;
	// int srcpID = 1;

	// initial dst array
	for(i=0;i<n;i++)                
		dis[i]=e[srcpID][i];
	for(i=0;i<n;i++)
		book[i]=0;
	book[srcpID]=1;
	//Dijkstra core lines
	for(i=0;i<n-1;i++){                        ////outter loop
	    //find the closest point to the point 0
		min=INF;
		for(j=0;j<n;j++)
		{
			if(book[j]==0&&dis[j]<min){       
				min=dis[j];
				u=j;
			}
		}
		book[u]=1;
		for(v=0;v<n;v++)
		{
			if(e[u][v]<INF)         
			{
				if(dis[v]>dis[u]+e[u][v])     
					dis[v]=dis[u]+e[u][v];
			}
		}
	}
	return 0;
}
