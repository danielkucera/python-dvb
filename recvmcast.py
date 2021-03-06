#!/usr/bin/env python

import socket
import binascii
import sys

def main():
  MCAST_GRP = sys.argv[1]
  MCAST_PORT = int(sys.argv[2])
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  except AttributeError:
     pass
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32) 
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

  sock.bind((MCAST_GRP, MCAST_PORT))
  sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton("0.0.0.0"))
  sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, 
                  socket.inet_aton(MCAST_GRP) + socket.inet_aton("0.0.0.0"))

  while 1:
    try:
      data, addr = sock.recvfrom(1316)
    except socket.error, e:
      print 'Expection'
#    hexdata = binascii.hexlify(data)
#    print 'Data = %s' % hexdata
    sys.stdout.write(data)

if __name__ == '__main__':
  main()
