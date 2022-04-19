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
    nohup $zroxy_path -p127.0.0.1:4433@443 -d 127.0.0.1:53000 -u8.8.8.8 -s127.0.0.1:58080 > /tmp/zroxy.txt &
    echo $!
}

function stop_zroxy ()
{
    echo $(kill -9 $1)
}

function domain_test ()
{
    org_ip=$(dig $1 A @8.8.8.8 +short -p53 +tcp +time=5 +tries=1 | head -n 1)
    zro_ip=$(dig $1 A @127.0.0.1 +short -p53000  +time=5 +tries=1 | head -n 1)
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

function sni_domain_test ()
{
    zro_con=$(curl --silent https://$1:4433 --resolve $1:4433:127.0.0.1 -H "Host: $1"| sha512sum)
    org_con=$(curl --silent https://$1 | sha512sum)
    if [ "$zro_con" = "$org_con" ]; then
        echo "pass"
    else
        echo "fail"
    fi
}

function sni_test ()
{
    domains=("ping.eu" "www.arngren.net" "google.com" "www.pacificgrandprix.com" "edition.cnn.com")
    for domain in ${domains[@]}; do
        res=$(sni_domain_test $domain)
        if [ "$res" = "pass" ]; then
            echo -e "SNI $C_YELLOW$domain$C_NoColor Test $C_GREEN$res$C_NoColor" >&2
        else
            echo -e "SNI $C_YELLOW$domain$C_NoColor Test $C_RED$res$C_NoColor" >&2    
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

echo -e "\nSNI test..."
res=$(sni_test)

#stop zroxy
echo -e "\nstop zroxy"
stop_zroxy $zroxy_pid

#stop socks proxy
echo "stop socks proxy"
stop_socks $socks_pid
