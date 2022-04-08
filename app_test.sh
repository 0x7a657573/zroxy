#!/bin/bash


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

function dns_test ()
{
    echo "start dns test..."
    sleep 5
}

zroxy=$1
echo "---- Start app test ----"

#start socks proxy
echo "start socks proxy"
socks_pid=$(start_socks)

#start zroxy
echo "start zroxy app"
zroxy_pid=$(start_zorxy $zroxy)

dns_test "ping.eu"

#stop zroxy
echo "stop zroxy"
stop_zroxy $zroxy_pid

#stop socks proxy
echo "stop socks proxy"
stop_socks $socks_pid
