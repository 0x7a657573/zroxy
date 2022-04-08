#!/bin/bash

C_RED="\033[0;31m"
C_GREEN="\033[0;32m"
C_WHITE="\033[1;37m"
C_NoColor="\033[0m"
C_YELLOW="\033[0;33m"

function start_socks () 
{
  PID=$(ssh -N 127.0.0.1 -D58080 & echo $!)
  echo $PID
}

function stop_socks ()
{
    echo $(kill -9 $1)
}

function start_zorxy ()
{
    zroxy_path=$1
    nohup $zroxy_path -d 0.0.0.0:53000 -u8.8.8.8 -s127.0.0.1:58080 > /tmp/zroxy.txt &
    echo $!
}

function stop_zroxy ()
{
    echo $(kill -9 $1)
}

function domain_test ()
{
    org_ip=$(dig $1 A @8.8.8.8 +short -p53 +tcp | head -n 1)
    zro_ip=$(dig $1 A @127.0.0.1 +short -p53000  | head -n 1)
    if [ "$org_ip" = "$zro_ip" ]; then
        echo "pass"
    else
        echo "fail"
    fi
}

function dns_test ()
{
    domains=("ping.eu" "blog.com" "bing.com" "wix.com" "gitlab.com")
    for domain in ${domains[@]}; do
        res=$(domain_test $domain)
        if [ "$res" = "pass" ]; then
            echo -e "Domain $C_YELLOW$domain$C_NoColor Test $C_GREEN$res$C_NoColor" >&2
        else
            echo -e "Domain $C_YELLOW$domain$C_NoColor Test $C_RED$res$C_NoColor" >&2    
        fi
    done
}

zroxy=$1
echo "---- Start app test ----"

#start socks proxy
echo "start socks proxy"
socks_pid=$(start_socks)

#start zroxy
echo "start zroxy app"
zroxy_pid=$(start_zorxy $zroxy)

sleep 0.5
echo -e "\ndsn test..."
res=$(dns_test)


#stop zroxy
echo "stop zroxy"
stop_zroxy $zroxy_pid

#stop socks proxy
echo "stop socks proxy"
stop_socks $socks_pid
