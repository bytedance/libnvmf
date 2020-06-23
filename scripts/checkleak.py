#!/bin/python
import sys

def process_mtrace(fname):
	alloc = {}
	linenum = 0
	with open(fname) as fp:
		for line in fp:
			linenum += 1
			elems = line.split()
			if elems[0] == '+':
				if elems[1] in alloc.keys(): 
					print ("Double malloc @%d: %s") % (linenum, line[:-1])
				else:
					alloc[elems[1]] = " @" + str(linenum) + " " + line[:-1]
			elif elems[0] == '-':
				if elems[1] in alloc.keys(): 
					alloc.pop(elems[1], None)
				else:
					print ("Double free @%d: %s") % (linenum, line[:-1])

	for k,v in alloc.items():
		print ("Unfreed: %s") % v

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print(sys.argv[0] + " nvmf-trace-file")
	else:
		process_mtrace(sys.argv[1])
