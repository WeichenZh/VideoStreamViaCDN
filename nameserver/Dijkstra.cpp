#include<stdio.h>

#define INF 65535

int dijkstra(int srcpID, int (*e)[20], int *dis, int *book, int nNodes, int nLinks){
	int min, i, j, v, u;
	int n = nNodes;
	int m = nLinks;
	// int srcpID = 1;

	//初始化dis数组，例如dis[3]=e[1][3],1到3距离为dis[3].
	for(i=0;i<n;i++)                
		dis[i]=e[srcpID][i];
	for(i=0;i<n;i++)
		book[i]=0;
	book[srcpID]=1;
	//Dj斯特拉算法核心语句
	for(i=0;i<n-1;i++){                        ////大循环，每一步控制1到i的最短路径。
	    //找到离一号顶点最近的顶点
		min=INF;
		for(j=0;j<n;j++)
		{
			if(book[j]==0&&dis[j]<min){        //以1号为例，1到2为1,1到3为12，u就是2.
				min=dis[j];
				u=j;
			}
		}
		book[u]=1;//j在内部循环，在外部要使用，用u保存j的值，常见思想。
		for(v=0;v<n;v++)
		{
			if(e[u][v]<INF)         //e[2][1]=inf,直到e[2][3]为9
			{
				if(dis[v]>dis[u]+e[u][v])     //dis[2]为1，dis[3]为12，dis[2]+e[2][3]=10,替换。
					dis[v]=dis[u]+e[u][v];
			}
		}
	}
	return 0;
}