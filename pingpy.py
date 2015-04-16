#!/usr/bin/env python
"""
    Pure-python realization of ping utility.
    Based on https://github.com/samuel/python-ping
    Supported features:
    - IPv4/IPv6
    - total timeout. like -w in ping
    - machine readable output in CLI
"""


import os
import sys
import socket
import struct
import select
import time
import random
import logging
import signal
import json
try:
    import netifaces
except ImportError:
    netifaces = None
if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time

ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_RESPONSE_TYPE = 0
ICMP_ECHO_REQUEST_CODE = 0
ICMP6_ECHO_REQUEST_TYPE = 128
ICMP6_ECHO_RESPONSE_TYPE = 129
ICMP6_ECHO_REQUEST_CODE = 0


class Timeout(Exception):
    pass


class Ping(object):
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.icmp_id = random.randint(0, 65535)
        self.logger.debug("my ICMP id=%s", self.icmp_id)
        self.seq_id = 0
        self.stat = {"min": 0, "max": 0, "count": 0, "sum": 0, "loss": 0}

    def msg_format(self, fmt, msg):
        pass

    def stat_append(self, rtt):
        if rtt is not 0:
            if self.stat['min'] > rtt or self.stat['min'] == 0:
                self.stat['min'] = rtt
            if self.stat['max'] < rtt:
                self.stat['max'] = rtt

            self.stat['sum'] += rtt
        else:
            self.stat['loss'] += 1

        self.stat['count'] += 1

    def make_stat(self):
        average = self.stat['sum'] / self.stat['count']
        if self.stat['count'] == 0:
            loss = 100
        elif self.stat['loss'] == 0:
            loss = 0
        else:
            loss = round(float(self.stat['loss']) / self.stat['count'] * 100, 2)
        res = {"min": round(self.stat['min'] * 1000, 2),
               "avg": round(average * 1000,2),
               "max": round(self.stat['max'] * 1000, 2),
               "loss": loss,
               "count": self.stat['count'],
               }
        return res

    def timeout_handler(self, signum, frame):
        self.logger.info("Signal handler called with signal %s", signum)
        raise Timeout()

    @classmethod
    def _carry_around_add(cls, a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)

    @classmethod
    def checksum(cls, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
            s = cls._carry_around_add(s, w)
        return ~s & 0xffff

    def receive_one_ping(self, my_socket, timeout):
        """
        receive the ping from the socket.
        return True if received. False if timeout
        """
        receive_start = default_timer()
        while True:
            what_ready = select.select([my_socket], [], [], timeout)
            if what_ready[0] == []:  # Timeout
                break

            rec_packet, sockaddr = my_socket.recvfrom(2048)
            if my_socket.family == socket.AF_INET:
                icmp_header = rec_packet[20:28]
            elif my_socket.family == socket.AF_INET6:
                icmp_header = rec_packet[0:8]
            pkt_icmp_type, code, pkt_checksum, pkt_icmp_id, sequence = struct.unpack(
                "BBHHH", icmp_header
            )
            if pkt_icmp_type in (ICMP_ECHO_RESPONSE_TYPE, ICMP6_ECHO_RESPONSE_TYPE) \
                    and pkt_icmp_id == self.icmp_id:
                return True
            if (default_timer() - receive_start) >= timeout:
                break
        return False

    def send_one_ping(self, my_socket, dest_host, ai_family, size=0):
        """
        Send one ping to the given >dest_host<.
        """
        my_checksum = 0
        self.seq_id += 1
        if ai_family == socket.AF_INET:
            icmp_type = ICMP_ECHO_REQUEST_TYPE
            icmp_code = ICMP_ECHO_REQUEST_CODE
        elif ai_family == socket.AF_INET6:
            icmp_type = ICMP6_ECHO_REQUEST_TYPE
            icmp_code = ICMP6_ECHO_REQUEST_CODE

        # Make a dummy header with a 0 checksum.
        header = struct.pack("BBHHH",
                             icmp_type,
                             icmp_code,
                             my_checksum,
                             self.icmp_id,
                             socket.htons(self.seq_id))
        data = size * "Q"

        # Calculate the checksum on the data and the dummy header.
        my_checksum = self.checksum(header + data)

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.

        header = struct.pack(
            "BBHHH",
            icmp_type,
            icmp_code,
            my_checksum,
            self.icmp_id,
            socket.htons(self.seq_id)
        )
        packet = header + data
        self.logger.debug("host=%s ai family=%s. seq id=%s",
                          dest_host,
                          ai_family,
                          self.seq_id)
        if ai_family == socket.AF_INET6:
            sockaddr = (dest_host, 0, 0, 0)
        elif ai_family == socket.AF_INET:
            sockaddr = (dest_host, 0)
        my_socket.sendto(packet, sockaddr)

    def do_one(self, addr, ai_family, timeout, bind, size=0):
        """
        Returns either the delay (in seconds) or none on timeout.
        """
        if ai_family == socket.AF_INET:
            icmp_proto = socket.getprotobyname("icmp")
        else:
            icmp_proto = socket.getprotobyname("ipv6-icmp")

        try:
            my_socket = socket.socket(ai_family, socket.SOCK_RAW, icmp_proto)
        except socket.error as (errno, msg):
            if errno == 1:
                # Operation not permitted
                msg += (
                    " - Note that ICMP messages can only be sent from processes"
                    " running as root."
                )
                raise socket.error(msg)
            raise  # raise the original error
        if bind:
            try:
                # addr
                socket.inet_aton(bind)
                src_addr = bind
            except socket.error:
                # iface
                if netifaces is None:
                    raise Exception("'netifaces' module not found ")
                ifaces = netifaces.ifaddresses(bind)
                if ai_family not in ifaces:
                    logger.critical("unable to find addr with specified IP version")
                    raise
                src_addr = ifaces[ai_family][0]['addr']
            self.logger.debug("use %s as source", src_addr)
            my_socket.bind((src_addr, 0))

        self.send_one_ping(my_socket, addr, ai_family, size)
        recv_status = self.receive_one_ping(my_socket, timeout)

        my_socket.close()
        return recv_status

    @classmethod
    def resolve(cls, dest_host, ai_family=None):
        if ai_family is None:
            ai_family = socket.AF_UNSPEC
        dest_addr = socket.getaddrinfo(dest_host,
                                       None,  # port
                                       ai_family,
                                       0,  # socket type
                                       0,  # proto
                                       )
        family, _, _, _, sockaddr = dest_addr[0]
        return family, sockaddr[0]

    def ping(self, dest_addr,
             timeout=2,
             count=4,
             ai_family=None,
             interval=1,
             total_timeout=None,
             quiet=True,
             bind=None,
             size=0,
             ):
        """
        Send >count< ping to >dest_addr< with the given >timeout< and display
        the result.
        """
        if total_timeout:
            signal.setitimer(signal.ITIMER_REAL, total_timeout)
            signal.signal(signal.SIGALRM, self.timeout_handler)
        try:
            family, addr = self.resolve(dest_addr, ai_family)
        except socket.gaierror as e:
            logger.critical("failed. (gai error: '%s')", e[1])
            return None  # error
        try:
            rtt = interval
            for i in range(count):
                wait = interval - rtt
                if wait > 0:
                    self.logger.debug("wait for %0.4ss", wait)
                    time.sleep(wait)
                self.logger.debug("ping %s", dest_addr)
                ping_start = time.time()
                ping_recv_status = self.do_one(addr, family, timeout, bind, size)
                rtt = time.time() - ping_start
                if ping_recv_status:
                    self.stat_append(rtt)
                    msg = "get ping in %0.4fms" % (rtt * 1000)
                else:
                    self.stat_append(0)  # loss
                    msg = "packet loss after %0.4fms" % (rtt * 1000)
                if not quiet:
                    print(msg)
            if total_timeout:
                signal.setitimer(signal.ITIMER_REAL, 0)
        except (Timeout, KeyboardInterrupt):
            self.logger.debug("timeout after")

        return self.make_stat()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='ping')
    parser.add_argument('destination',
                        type=str,
                        help='destination host')
    parser.add_argument('-c',
                        type=int,
                        default=3,
                        metavar='count',
                        help='stop after sending count ECHO_REQUEST packets. '
                             'With deadline option, ping waits for count ECHO_REPLY'
                             ' packets, until the timeout expires')
    ipv_group = parser.add_mutually_exclusive_group()
    ipv_group.add_argument('-4',
                           action='store_true',
                           help='IPv4')
    ipv_group.add_argument('-6',
                           action='store_true',
                           help='IPv6')
    parser.add_argument('-w',
                        type=float,
                        metavar='deadline',
                        help='''specify a timeout, in seconds, before ping exits regardless of
                        how many packets have been sent or received. In this case ping does
                        not stop after count packet are sent, it waits either for deadline expire or
                        until count probes are answered or for some error
                        notification from network''')
    parser.add_argument('-i',
                        type=float,
                        metavar='interval',
                        default=1,
                        help='''wait interval seconds between sending each packet.
                        The default is to wait for one second between each packet normally, or not
                        to wait in flood mode.''')
    parser.add_argument('-s',
                        type=int,
                        metavar='size',
                        default=0,
                        help='packet size')
    parser.add_argument('-d',
                        action='store_true',
                        help='enable debug')
    parser.add_argument('-q',
                        action='store_true',
                        help='quiet')
    parser.add_argument('-o',
                        choices=['json', 'csv', 'text'],
                        default='text',
                        help='output format')
    parser.add_argument('-B',
                        default=None,
                        metavar="host or interface",
                        help='''source address or interface.
                        If interface specified (need python-netifaces), some address from this iface will be used as source address.''')
    args = parser.parse_args()

    basic_log_format = '%(asctime)s - l:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s'
    date_fmt = '%Y-%m-%d %H:%M:%S'
    logger = logging.getLogger(__name__)
    if args.d:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.ERROR

    logger.setLevel(loglevel)
    logger_handler = logging.StreamHandler()
    formatter = logging.Formatter(basic_log_format, date_fmt)
    logger_handler.setFormatter(formatter)
    logger.addHandler(logger_handler)

    target = args.destination
    if args.__dict__['4']:
        ipver = 4
    elif args.__dict__['6']:
        ipver = 6
    else:
        ipver = None
    pinger = Ping()

    if ipver == 6:
        ai_family = socket.AF_INET6
    elif ipver == 4:
        ai_family = socket.AF_INET
    else:
        ai_family = socket.AF_UNSPEC

    _old_excepthook = sys.excepthook

    def myexcepthook(exctype, value, traceback):
        if exctype == KeyboardInterrupt:
            pinger.timeout_handler(signal.SIGINT, None)
        else:
            _old_excepthook(exctype, value, traceback)

    sys.excepthook = myexcepthook

    if args.o != "text":
        quiet = True
    else:
        quiet = args.q

    stat = pinger.ping(target,
                       count=args.c,
                       ai_family=ai_family,
                       interval=args.i,
                       total_timeout=args.w,
                       quiet=quiet,
                       bind=args.B,
                       size=args.s,
                       )
    if stat is None:
        print >>sys.stderr, "error"
        sys.exit(1)
    if args.o == "text":
        print("rtt in ms,min=%0.3f,avg=%0.3f,max=%0.3f,count=%s,loss=%s%%" % (
              stat['min'],
              stat['avg'],
              stat['max'],
              stat['count'],
              stat['loss'],
              ))
    elif args.o == "csv":
        print("min,avg,max,count,loss")
        print(",".join([str(stat[x]) for x in ('min', 'avg', 'max', 'count', 'loss')]))
    elif args.o == "json":
        print(json.dumps(stat))


