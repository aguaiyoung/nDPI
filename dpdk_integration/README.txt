************************************************************************
Overview
************************************************************************

This is an integration example in a DPDK environment.
The application uses two lcore to dispatch packets
from an ethernet queue in each processing lcore software queue.
This uses a software hash to dispatch packets through different processing queues.

If your NIC has a symmetric RSS hardware hash feature, you can use it
to dispatch packets as pictured below.


                    +----------------------------+
                    |       ethernet PORT        |
                    +----------------------------+
                       +------+       +------+ 
                       |Queue1|       |Queue2| 
		       |Lcore0|       |Lcore1|
                       +------+       +------+ 
                         |               |
                         |               |
                         v               v
                   +--------------------------------+
                   |   Master lcore (dispatch)      |
                   +--------------------------------+
                        |       |        |       |
                        |       |        |       |
                        v       v        v       v 
                   +------+ +------+ +------+ +-----=+
                   |      | |      | |      | |      |
                   |Queue3| |Queue4| |Queue5| |QueueN|   
                   |  SW  | |  SW  | |  SW  | |  SW  |
                   |      | |      | |      | |      |
                   +------+ +------+ +------+ +------+
                        |       |        |       |
                        |       |        |       |
                        v       v        v       v 
                    +------+ +------+ +------+ +------+
                    |      | |      | |      | |      |
                    |Lcore2| |Lcore3| |Lcore4| |LcoreN|
                    |      | |      | |      | |      |
                    +------+ +------+ +------+ +------+
                        |       |        |       |
                        |       |        |       |
                        v       v        v       v

                               DPI

************************************************************************
DPDK Version
************************************************************************
This application was written and tested using DPDK stable
version 17.11.5 (LTS)

************************************************************************
Installation
************************************************************************
RTE_SDK and RTE_TARGET variables should be set as recommended by dpdk
manual, see also http://dpdk.org/doc/quick-start

make: build application
make install:  install application in src/bin directory

Notes:
build is dynamic by default.
Set STATIC=1 for static build.
Set DEBUG=1 to get debug info.

************************************************************************
Usage
************************************************************************
To get full usage, just type: ./dpdk_integration

Example usage:

To run on 4 threads :
./dpdk_integration -l 0,1,2,3,4 -n 4
or
./dpdk_integration -c 0xF -n 4

To add or change ixEngine parameter :
./dpdk_integration -c 0xF -n 4 -- --no_print --nb_flows 10000

Please verify that the dispatching and the working threads are
running on the same NUMA node as the NIC port.

The LD_LIBRARY_PATH variable can be set as follows from this directory:
$ export LD_LIBRARY_PATH=../../../lib

************************************************************************
Troubleshooting
************************************************************************
Packets errors in DPI
  - You may need to increase the number of flows per worker (nb_flows).
***********************************************************************
Changelog
************************************************************************
1.修改了dpdk多队列，以pipline模式，默认2核收发，core0统计,core1/2做收发,其他核做dpi
2.增加了--receiver 和 --hash 命令行选项修改收发核数量，hash方式支持qmdpi二元组/五元组方式 以及dpdk硬件mbuf.rss以及软件计算二元/五元组/以及roundrobin方式
3.修改了统计，增加了入环方向的pps 丢包pps(只统计了一个核）的统计，修改了以pps/Mbps统计粒度
4.修改了Makefile,增加对高版本gcc支持。
5.支持dpdk低版本向下兼容（以17.11.2为主测试 去除了相关API） ring环创建是多生产者单消费者模型
