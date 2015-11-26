#!/usr/bin/env python

import socket
import binascii
import sys
import time
import datetime

counter = {}

def main():
#  MCAST_GRP = '239.114.221.33' 
#  MCAST_PORT = 1234
  oldpacket = ""

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
  host = socket.gethostbyname(socket.gethostname())
  sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
  sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, 
                  socket.inet_aton(MCAST_GRP) + socket.inet_aton(host))

  pktCnt = 0
  scrambledCnt = 0
  CCerrors = 0
  haveStream = False
  lastTime = 0

  while 1:
    try:
      data, addr = sock.recvfrom(1316)
    except socket.error, e:
      print 'Expection'

    if not haveStream:
	haveStream = True
	print "Have stream"

    if lastTime + 1 < time.time():
	print (round(float(scrambledCnt)/(pktCnt + 1)*100)), "%crypt,",
	print CCerrors, "CCerr,",
	print (pktCnt*188*8)/1024, "Kbps,",
	print "PIDs:",counter.keys(),
	sys.stdout.flush()
	print "\r",
	pktCnt = 0
	scrambledCnt = 0
	lastTime = time.time()

    while len(data) > 0:
    	pktCnt += 1
	packet = data[:188]
	data = data[188:]
	PID = ord(packet[2]) + (ord(packet[1]) % 32) * 256
	CC = ord(packet[3]) % 16
	hasPayload = (ord(packet[3]) & 16) != 0
	scrambled = (ord(packet[3]) & 0xc0) !=0

	if scrambled:
		scrambledCnt += 1

	#print MCAST_GRP, CC

	if packet == oldpacket:
		#sys.stdout.write('D')
#		print "DUP!"
		a=0

	if (PID in counter) and (counter[PID] + 1 != CC) and (CC != 0) and hasPayload:
	    print datetime.datetime.now(),"ccerror", MCAST_GRP, PID, "expected", counter[PID] + 1, "got", CC
	    CCerrors += 1

	counter[PID] = CC
	oldpacket = packet



if __name__ == '__main__':
  main()
