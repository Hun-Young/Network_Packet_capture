#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h> // ether_header *
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>

void err_quit(const char *message);
void err_sys (const char *message);
void menu();
void sel_pro();
void sel_app();
void PrintData(unsigned char *data, int Size);
void print_tcp_packet(unsigned char* Buffer, struct iphdr *iph);
void print_udp_packet(unsigned char* Buffer, struct iphdr *iph);
void tcpPrint(unsigned char *Buffer, struct tcphdr *tcph, char *tmp, char *tmp2);
void view_set();
void sig_handler(int signo);

int sel_menu=1;
int sel_protocol=0;
int Size;
int fil_tcp[3]={1,1,1};	// telnet, ftp, HTTP 캡쳐 여부확인	1 = Yes	0 = No
int fil_udp[1]={1}; //DNS
	FILE *fp;	//파일 오픈을 위한 포인터 
struct sockaddr_in source ,dest;

int main(int argc, char *argv[]){
	system("clear");
	menu();

	char now[40]="./log/log";
	time_t t=time(NULL);
	struct tm tm=*localtime(&t);
	char year[10];
	char mon[10];
	char mday[10];
	char hour[10];
	char min[10];
	char sec[10];
	printf("now: %d-%d-%d %d:%d:%d\n",
       tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
       tm.tm_hour, tm.tm_min, tm.tm_sec);

        sprintf(year,"%d",tm.tm_year+1900);
	sprintf(mon,"%d",tm.tm_mon+1);
	sprintf(mday,"%d",tm.tm_mday);
	sprintf(hour,"%d",tm.tm_hour);
	sprintf(min,"%d",tm.tm_min);
	sprintf(sec,"%d",tm.tm_sec);
	strcat(now,year);	strcat(now,"-");
	strcat(now,mon);	strcat(now,"-");
	strcat(now,mday);	strcat(now,"_");
	strcat(now,hour);	strcat(now,"-");
	strcat(now,min);	strcat(now,"-");
	strcat(now,sec);	strcat(now,".txt");

	fp = fopen(now, "at+"); // report.txt를 만들고 수정

    int sockfd; // raw socket 생성
    if ((sockfd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
        err_sys("socket error");

	signal(SIGINT,sig_handler); //Ctrl^c 입력 시 캡쳐 종료 시그널


    for ( ; ; ){	
        uint8_t buff[ETH_FRAME_LEN];
        int n, i; // raw data 수신
        if ((n = read(sockfd,buff,ETH_FRAME_LEN))<0)
            err_sys("read error");
	Size=n;
struct iphdr *iph = (struct iphdr *)((void*)buff+sizeof(struct ether_header));                  //IP헤더 선언

memset(&source, 0, sizeof(source));
source.sin_addr.s_addr=iph->saddr;

memset(&dest, 0, sizeof(dest));
dest.sin_addr.s_addr=iph->daddr;
unsigned short iphlen;
iphlen=iph->ihl*4;
if(iph->protocol==6 ||iph->protocol==17){
	switch(iph->protocol) //Ip header->protocol 값 비교 
    	{ 	 
       	 case 6: //  tcp값을 받을 경우
	{ 
	print_tcp_packet(buff,iph);
            break;  
	}
        case 17:  // UDP일 경우
	{
	print_udp_packet(buff, iph);
   	 break;  
	}
        default:  // 그 외일 경우
            break;  
    	}  
	}
    }
	fclose(fp); //  파일 끝내기
}

 
void print_tcp_packet(unsigned char *Buffer,struct iphdr *iph){
struct tcphdr *tcph =(struct tcphdr *)(Buffer+sizeof(struct ether_header)+ sizeof(struct iphdr)); //tcp헤더 선언
	char tmp[10];
	char tmp2[10];
     	int a =ntohs(tcph->dest);
        int b =ntohs(tcph->source);
 if(((a==23)||(b==23))&&(fil_tcp[0]==1)){ // telnet일 경우
	if(a==23) strcpy(tmp,"Telnet"); 
	else sprintf(tmp,"%d",a);
	if(b==23) strcpy(tmp2,"Telnet");
	else sprintf(tmp2, "%d",b);

	tcpPrint(Buffer, tcph, tmp, tmp2);
        }

 else if((((a==21)||(b==21))||((a==20)||(b==20)))&&(fil_tcp[1]==1)){  // ftp일 경우
	if(a==21) strcpy(tmp,"FTP21");
	else if(a==20) strcpy(tmp,"FTP20");
        else sprintf(tmp,"%d",a);

        if(b==21) strcpy(tmp2,"FTP21");
	else if(b==20) strcpy(tmp,"FTP20");
        else sprintf(tmp2, "%d",b);

	tcpPrint(Buffer, tcph, tmp, tmp2);
        }

 else if(((a==80)||(b==80))&&(fil_tcp[2]==1)){   // HTTP일 경우
	if(a==80) strcpy(tmp,"HTTP");
	else sprintf(tmp,"%d",a);
        if(b==80) strcpy(tmp2,"HTTP");
        else sprintf(tmp2, "%d",b);

	tcpPrint(Buffer, tcph, tmp, tmp2);
	}
}

void tcpPrint(unsigned char *Buffer, struct tcphdr *tcph, char *tmp, char *tmp2){ 
unsigned short iphdrlen;
 struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
int header_size =sizeof(struct iphdr *) + iphdrlen + tcph->doff*4;

		printf("\n== Protocol             : TCP\n");
                printf("Source IP ------------->Destination IP\n");
                printf("  <%s> ---------><",inet_ntoa(source.sin_addr));
		printf("%s>\n",inet_ntoa(dest.sin_addr));
                printf("Application------------>Destination\n");
                printf("  <%s> ------------> <%s>\n",tmp, tmp2);
                printf("sequence                : %u\n", ntohl(tcph->seq));
                printf("Acknowledge Number      : %u\n", ntohl(tcph->ack_seq));
                printf("res1    : %d            ack : %d\n",(unsigned int)tcph->res1,(unsigned int)tcph->ack);
                printf("push    : %d            ece : %d\n",(unsigned int)tcph->psh,(unsigned int)tcph->ece);
                printf("check   : %x         rst : %d\n",(unsigned int)ntohs(tcph->check),(unsigned int)tcph->rst);
                printf("fin     : %d            syn : %d\n",(unsigned int)tcph->fin,(unsigned int)tcph->syn);


                fprintf(fp,"\n== Protocol               : TCP\n");
		fprintf(fp,"Source IP ------------->Destination IP\n");
                fprintf(fp,"  <%s> ---------><",inet_ntoa(source.sin_addr));
                fprintf(fp,"%s>\n",inet_ntoa(dest.sin_addr));
                
                fprintf(fp,"Application------------>Destination\n");
                fprintf(fp,"  <%s> ------------> <%s>\n",tmp, tmp2);
                fprintf(fp,"sequence            : %u\n", ntohl(tcph->seq));
                fprintf(fp,"Acknowledge Number  : %u\n", ntohl(tcph->ack_seq));
                fprintf(fp,"res1    : %d                ack : %d\n",(unsigned int)tcph->res1,(unsigned int)tcph->ack);
                fprintf(fp,"push    : %d                ece : %d\n",(unsigned int)tcph->psh,(unsigned int)tcph->ece);
                fprintf(fp,"checksum: %x                rst : %d\n",(unsigned int)ntohs(tcph->check),(unsigned int)tcph->rst);
                fprintf(fp,"fin     : %d                syn : %d\n",(unsigned int)tcph->fin,(unsigned int)tcph->syn);

	PrintData(Buffer,Size);
}


void print_udp_packet(unsigned char *Buffer, struct iphdr *iph){
unsigned short iphdrlen;
    iphdrlen = iph->ihl*4;

struct udphdr *udph=(struct udphdr *)(Buffer+sizeof(struct ether_header)+sizeof(struct iphdr));            //udp 헤더 설정

int header_size =sizeof(struct ethhdr) + iphdrlen + sizeof(udph);

	char tmp[10];
        char tmp2[10];
        int a =ntohs(udph->dest);
        int b =ntohs(udph->source);
        if(a==53) strcpy(tmp,"DNS");
        else sprintf(tmp,"%d",a);

        if(b==53) strcpy(tmp2,"DNS");
        else sprintf(tmp2, "%d",b);
                if(((a==53)||(b==53))&&(fil_udp[0])){ // DNS일 경우
                printf("\n== Protocol		: UDP\n");
		printf("Source IP ------------->Destination IP\n");
                printf("  <%s> ---------><",inet_ntoa(source.sin_addr));
                printf("%s>\n",inet_ntoa(dest.sin_addr));
                
	        printf("Application------------>Destination\n");
         	printf("  <%s> ------------> <%s>\n",tmp, tmp2);
		printf("Len :	%d		check : %x\n",ntohs(udph->len), ntohs(udph->check));

                fprintf(fp,"\n== Protocl		: UDP\n");
                fprintf(fp,"Source IP ------------->Destination IP\n");
                fprintf(fp,"  <%s> ----------><",inet_ntoa(source.sin_addr));
                fprintf(fp,"%s>\n",inet_ntoa(dest.sin_addr));
	        fprintf(fp,"Application------------>Destination\n");
                fprintf(fp,"  <%s> ------------> <%s>\n",tmp, tmp2);
		fprintf(fp,"Len : %d              check : %x\n",ntohs(udph->len), ntohs(udph->check));

        PrintData(Buffer,Size);
		}
}

void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
		fprintf(fp,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128){
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                fprintf(fp,"%c",(unsigned char)data[j]);
		 }
                else{ printf("."); //otherwise print a dot
			fprintf(fp,".");
            }
		}
            printf("\n"); fprintf(fp,"\n");
        } 
         
        if(i%16==0){ printf("   "); fprintf(fp,"   "); }
            printf(" %02X",(unsigned int)data[i]);
           fprintf(fp," %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              printf("   "); //extra spaces
		fprintf(fp,"   "); //extra spaces

            }
             
            printf("         ");
            fprintf(fp,"         ");
 
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  printf("%c",(unsigned char)data[j]);
			fprintf(fp,"%c",(unsigned char)data[j]);
                }
                else
                {
                  printf(".");	fprintf(fp,".");
                }
            }
            printf("\n" );
		fprintf(fp,"\n" );
        }
    }
}
void err_quit(const char *message){
    fputs(message,stderr);
    fputc('\n' ,stderr);
    exit(1);
}


void err_sys(const char *message){
    exit(1);
}

void menu(){			// menu 인터페이스 
printf("=======================\n");
printf("Pactket Capture System \n");
printf("=======================\n");
printf("1.Capture Packet\n");		// 캡쳐 시작
printf("2.Filtter Setting\n");		// 필터 세팅
printf("3.View Settings\n");		// 현재 필터 확인
printf("0.Exit\n");
printf(">>>");

scanf("%d",&sel_menu);
	system("clear");
	if(sel_menu==1){
	printf("Capturing Start!!!!\n");
	}

	else if(sel_menu==2){
	sel_pro();
	}
	else if(sel_menu==3){
	view_set();
	}
	else if(sel_menu==0){
	exit(1);
	}
	else
	printf("Please select correct menu ... \n");
}

void sel_pro(){	//protocol 설정 인터페이스
printf("======================\n");
printf("    Select Protocol   \n");
printf("=====================\n");
printf("1. TCP\n");
printf("2. UDP\n");
printf("0. back\n");
printf(">>>");
scanf("%d",&sel_protocol);
system("clear");
	if(sel_protocol==0){
	menu();
	}
	else if(sel_protocol<=2)
	{
	sel_app();
	}
	else
	{
	sel_pro();
	printf("Please select correct Protocol ... \n");
	}
}

void sel_app(){	//application 설정 인터페이스
int i=0;
printf("=====================\n");
printf("     Select App      \n");
printf("=====================\n");
	if(sel_protocol==1){ //TCP를 선택했을 경우
	printf("1. Telnet\n");
	printf("2. FTP\n");
	printf("3. HTTP\n");
	printf("0.back\n");
	printf(">>>");
	scanf("%d",&i);
	system("clear");
		if(i==0){
		sel_pro();
		}
		else if(i<=3){
			if(fil_tcp[i-1]==1)	fil_tcp[i-1]=0;
			else if(fil_tcp[i-1]==0) fil_tcp[i-1]=1;
		printf("TCP setting complete!\n");
		sel_app();
		}
		else{
		sel_app();
		printf("Please select correct TCP ... \n");
		}
	}
	else if(sel_protocol==2){ // UDP를 선택했을 경우
	int j=0;
	printf("1. DNS\n");
	printf("0. back\n");
	printf(">>>");
	scanf("%d",&j);
	system("clear");
		if(j==0){
		sel_pro();
		}
		else if(j==1)
		{
			if(fil_udp[j-1]==1)	fil_udp[j-1]=0;
			else if(fil_udp[j-1]==0) fil_udp[j-1]=1;
			printf("UDP setting complete!\n");
			sel_app();
		}
		else{
		printf("Please select correct UDP ... \n");
		sel_app();
		}
	}
}

void view_set()		// 현재 필터 세팅 확인
{
char *tmp;
system("clear");
printf("=====================\n");
printf("	TCP\n");
//fprintf(fp,"=====================\n");
//fprintf(fp,"	TCP\n");
	if(fil_tcp[0]==0) tmp="No";
	else tmp="Yes";		
	printf("telnet :	%s\n",tmp);	
	//fprintf(fp,"telnet :	%s\n",tmp);
	if(fil_tcp[1]==0) tmp="No";
	else tmp="Yes";
	printf("ftp :		%s\n",tmp);
	//fprintf(fp,"ftp :		%s\n",tmp);
	if(fil_tcp[2]==0) tmp="No";
	else tmp="Yes";
	printf("HTTP :		%s\n",tmp);
	//fprintf(fp,"HTTP :		%s\n",tmp);
printf("======================\n");
printf("	UDP\n");
//fprintf(fp,"======================\n");
//fprintf(fp,"	UDP\n");
	if(fil_udp[0]==0)	tmp="No";
	else tmp="Yes";
	printf("DNS : 		%s\n\n\n",tmp);
	//fprintf(fp,"DNS : 		%s\n\n\n",tmp);
menu();
}

void sig_handler(int signo){	// Ctrl^c 시그널로 캡쳐 중지
system("clear");
printf("Capture stop!\n");
menu();
}
