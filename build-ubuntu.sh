#!/usr/bin/env bash


apt-get install -y build-essential
apt-get install -y autoconf libtool git libpcap-dev pkg-config xtables-addons-source subversion

apt-get install -y git
apt-get install -y libtool
apt-get install -y autoconf
apt-get install -y automake
apt-get install -y pkg-config
apt-get install -y subversion
apt-get install -y libpcap-dev
apt-get install -y iptables-dev
apt-get install -y linux-source linux-headers-`uname -r`

ln -s /usr/src/linux-headers-`uname -r` /lib/modules/`uname -r`/build

cd /usr/src/ndpi-netfilter

cd nDPI && ./autogen.sh && ./configure && make && make install && cd ..

cd src && rm -rf ndpi_cpy && rm -f built-in.a main.o .built-in.a.cmd .main.o.cmd && cd ..
NDPI_PATH=/usr/src/ndpi-netfilter/nDPI make
make modules_install

cp /usr/src/ndpi-netfilter/ipt/libxt_ndpi.so /lib/xtables/
cp /usr/src/ndpi-netfilter/ipt/libxt_ndpi.so  /usr/lib/x86_64-linux-gnu/xtables/

# disable module
modprobe -r xt_ndpi
# enable module
modprobe xt_ndpi

iptables -m ndpi --help

iptables -C INPUT -i tun+ -m ndpi --bittorrent -j DROP
