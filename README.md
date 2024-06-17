# crash

```shell
mod -s xt_ndpi /usr/src/ndpi-netfilter/src/xt_ndpi.ko
```
 

This package is a GPL implementation of an iptables and netfilter module for
nDPI integration into the Linux kernel 5.4+.

It is based on an initial implementation for Ubuntu 14.04 by [Humberto
Jucá](https://github.com/betolj/ndpi-netfilter), recently updated for
Ubuntu 20.04 by
[prizraksarvar](https://github.com/prizraksarvar/ndpi-netfilter) with
refinements by [Chris
Nelson](https://github.com/ChrisNelson-CyberReef).

# Prerequisites

Earlier versions of this module included documentation for
reconfiguring the 2.x kernel to enable the required Netfilter
Connection Tracking.  Around version 4.16 of the kernel, that was
turned on by default so kernel changes are no longer required; this
should work on generic Ubuntu 20.04.

You _will_ need kernal headers and some other packages to build and
install this module.

```
  apt-get install -y libtool
  apt-get install -y pkg-config
  apt-get install -y libpcap-dev
  apt-get install -y libxtables-dev
  apt-get install -y libip6tc-dev
  apt-get install -y libip4tc-dev
  apt-get install -y libjson-c-dev
  apt-get install -y linux-source linux-headers-`uname -r`
  ln -s /usr/src/linux-headers-`uname -r` /lib/modules/`uname -r`/build
```

# nDPI

This module depends on
[nDPI](https://www.ntop.org/products/deep-packet-inspection/ndpi/),
"Open and Extensible LGPLv3 Deep Packet Inspection Library."  Their [GitHub repository](https://github.com/ntop/nDPI) is used as a submodule of this repository.  You must clone this repository with a command like:

```
  git clone --recurse-submodules https://github.com/TechTeamCR/ndpi-netfilter
```

With that done, go to where you cloned the code and do:

```
  git submodule sync
  git submodule update
  cd nDPI
  ./autogen.sh && ./configure && make
  sudo make install
```

# Building the module

The `ndpi-netfilter` build needs to know where to find the nDPI source (built in the previous step).  Specify the `NDPI_PATH` with a command like:

```
  NDPI_PATH=`pwd`/nDPI make
  sudo make modules_install
  sudo mkdir /lib/xtables/
  sudo cp ipt/libxt_ndpi.so /lib/xtables/
  sudo cp ipt/libxt_ndpi.so /usr/lib/x86_64-linux-gnu/xtables/
```

# Loading the Module

You can remove the previous version of the module, if any, with:

```
  sudo modprobe -r xt_ndpi
```

You can install the current version of the module with:

```
  sudo modprobe xt_ndpi
```

# Enabling Connection Tracking

Connection tracking must be turned on in iptables with a command like:

```
  sudo iptables -t mangle -C PREROUTING -m conntrack --ctstate INVALID -j DROP 
```

or

```
  sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

# Testing

You can see the protocols supported by this module with:

```
  iptables -m ndpi --help
```

You can block Youtube traffic with:

```
  sudo iptables -t mangle -A PREROUTING -m ndpi --youtube -j DROP
```
