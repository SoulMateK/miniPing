#include <signal.h> /*signal()*/
#include <stdio.h>
#include <pthread.h>
#include <sys/time.h> /*struct timeval*/
#include <netinet/in.h> /*unknow*/
#include <netinet/ip.h> /*unknow*/
#include <netinet/ip_icmp.h> /*unknow*/
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#define PACKET_SIZE     4096
typedef struct ping_packet
{
	struct timeval tv_begin;
	struct timeval tv_end;
	short seq;
	int flag;
}ping_packet;

ping_packet pingpacket[128];
int live = 0;
int sockfd = 0;
struct sockaddr_in dest;
int send_num = 0;
int recv_num = 0;
int datalen = 56;
char dest_str[80];
char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
struct timeval tv_begin, tv_end, tv_interval;
pid_t pid;

struct timeval icmp_tvsub(struct timeval end, struct timeval begin)
{
    struct timeval tv;
    tv.tv_sec = end.tv_sec - begin.tv_sec;
    tv.tv_usec = end.tv_usec - begin.tv_usec;
    if(tv.tv_usec < 0){
        tv.tv_sec --;
        tv.tv_usec += 1000000;
    }
    // printf("%d\n", tv.tv_sec);
    return tv;
}

void signal_handle(int signo)
{
	live = 0;
	gettimeofday(&tv_end,NULL);
	tv_interval = icmp_tvsub(tv_end, tv_begin);
	printf("Bye\n");
}

void statistics_packets()
{
	double time = (tv_interval.tv_sec * 1000) + (double)tv_interval.tv_usec / 1000;
	printf("--- %s ping statistics ---\n", dest_str);  
    printf("%d packets transmitted, %d received, %d%c packet loss, time %.2f ms\n",   
        send_num,recv_num,(send_num-recv_num)*100/send_num,'%',time);
}

ping_packet *find_packet(int seq)
{
    int i;
    ping_packet *found = NULL;
    if(seq == -1)
    {
        for(i=0;i<128;i++){
            if(pingpacket[i].flag == 0){
                found = &pingpacket[i];
                break;  
            }
        }
    }
    else 
    {
        for(i =0 ;i< 128;i++){
            if(pingpacket[i].seq == seq){
                found = &pingpacket[i];
                break;
            }
        }
    }
    return found;
 }

unsigned short cal_chksum(unsigned short *addr,int len)
{
	int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;
	
    while(nleft > 1)
    {       
    	sum += *w++;
        nleft -= 2;
    }
    if(nleft == 1)
    {       
    	*(unsigned char *)(&answer)=*(unsigned char *)w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

int pack(int packet_no)
{
	int i, packsize;
	struct icmp *icmp;
	struct timeval *tval;

	icmp = (struct icmp*)sendpacket;
	icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = packet_no;
    icmp->icmp_id = pid;
    packsize = 8 + datalen;
    tval = (struct timeval *)icmp->icmp_data;
    gettimeofday(tval, NULL);
    icmp->icmp_cksum = cal_chksum((unsigned short *)icmp, packsize);
    return packsize;
}

int unpack(char *buf, int len)  
{  
    int i,iphdrlen;
    struct ip *ip = NULL;
    struct icmp *icmp = NULL;
    double rtt;
  
    ip = (struct ip *)buf;
    iphdrlen = ip->ip_hl * 4;
    icmp = (struct icmp *)(buf+iphdrlen);
    len -= iphdrlen;
    if(len < 8){
        printf("ICMP packets\'s length is less than 8\n");
        return -1;
    }
    
    if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid)){
        struct timeval tv_interval, tv_recv, tv_send;
        
        ping_packet *packet = find_packet(icmp->icmp_seq);
        if(packet == NULL)
            return -1;
        tv_send = packet->tv_begin;
  
        gettimeofday(&tv_recv, NULL);
        tv_interval = icmp_tvsub(tv_recv, tv_send);
        rtt = tv_interval.tv_sec * 1000 + (double)tv_interval.tv_usec/1000;
        printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.2f ms\n", 
            len,inet_ntoa(ip->ip_src),icmp->icmp_seq,ip->ip_ttl,rtt);
        recv_num ++;
        packet->flag = 0;
    }
    else {
        return -1;
    }
}

void *send_icmp(void *param)
{
	
	while(live) {
	    int size = 0;
	    struct timeval tv;
	    gettimeofday(&tv, NULL);
	    ping_packet *packet = find_packet(-1);
	    if (packet)
	    {
	    	packet->seq = send_num + 1;
	    	packet->flag = 1;
	    	gettimeofday(&packet->tv_begin, NULL);
	    }
	    size = pack(send_num + 1);
        if(sendto(sockfd, sendpacket, size, 0, 
        	(struct sockaddr *)&dest, sizeof(dest)) < 0){
            perror("sendto error");
            continue;
        }
        send_num++;
        sleep(1);
	}
}

void *recv_icmp(void *param)
{
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 200;
	fd_set readfd;

	while(live) {
	    int ret = 0;
	    FD_ZERO(&readfd);
	    FD_SET(sockfd, &readfd);
	    ret = select(sockfd+1, &readfd, NULL, NULL, &tv);
	    switch(ret)
	    {
	    	case -1:
	    	break;

	    	case 0:
	    	break;

	    	default :
	    	{
	    		int fromlen = 0;
	    		struct sockaddr from;
	    		int size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);
	    		if (errno == EINTR)
	    		{
	    			perror("recvfrom error");
	    			continue;
	    		}
	    		ret = unpack(recvpacket, size);
	    		if (ret == 1)
	    		{
	    			continue;
	    		}
	    	}
	    }
	}
}

int main(int argc, char const *argv[])
{
	struct hostent *host = NULL;
	struct protoent *protocol;
	unsigned long inaddr = 1;
	int size = 128 * PACKET_SIZE;


	signal(SIGINT, signal_handle);
	pid = getpid();
	if (argc < 2)
	{
		printf("ping aaa.bbb.ccc.ddd or DNS address\n");
		return -1;
	}
	if ((protocol = getprotobyname("icmp")) == NULL)
	{
		perror("getprotobyname");
		return -1;
	}
	if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)
	{
		perror("socket error");
		return -1;
	}
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;

	inaddr = inet_addr(argv[1]);  
    if(inaddr == INADDR_NONE)
    {
        host = gethostbyname(argv[1]);
        if(host == NULL)
        {
            perror("gethostbyname");  
            return -1;  
        }
        memcpy((char *)&dest.sin_addr, host->h_addr, host->h_length);  
    }
    else
    {
        memcpy((char *)&dest.sin_addr, &inaddr,sizeof(inaddr));
    }
    memcpy(dest_str, argv[1],strlen(argv[1])+1);
	memset(pingpacket, 0, sizeof(ping_packet) * 128);

    live = 1;
    pthread_t send_pd, recv_pd;
    gettimeofday(&tv_begin, NULL);
    if (pthread_create(&send_pd, NULL, send_icmp, NULL) < 0)
    {
    	return -1;
    }
    if (pthread_create(&recv_pd, NULL, recv_icmp, NULL) < 0)
    {
    	return -1;
    }
    pthread_join(send_pd, NULL);
    pthread_join(recv_pd, NULL);

    close(sockfd);
    statistics_packets();
	return 0;
}