#!/bin/python
# Emulating network card link up/down to test reconnection of libnvmf
# 
# Copyright 2022 zhenwei pi
#
# Authors:
#   zhenwei pi
# This work is licensed under the terms of the GNU GPL, version 2 or later.
# See the COPYING file in the top-level directory.

import os
import random
import sys
import time

def network_on():
	cmd = 'iptables -D OUTPUT -p tcp --dport 4420 -j DROP'
	print "Network On: " + cmd
	os.system(cmd)

def network_off():
	cmd = 'iptables -A OUTPUT -p tcp --dport 4420 -j DROP'
	print "Network Off: " + cmd
	os.system(cmd)

if __name__ == '__main__':
	while (1):
		try:
			rand = random.randint(1, 60)
			print "Sleep " + str(rand) + " seconds"
			time.sleep(rand)
			network_off()
			rand = random.randint(1, 60)
			print "Sleep " + str(rand) + " seconds"
			time.sleep(rand)
			network_on()
		except KeyboardInterrupt:
			network_on()
			sys.exit(0)
