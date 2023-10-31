
import sys

def writeOutputZone(lookups, outFile=sys.stdout, ttl=600):
	for name in list(lookups.keys()):
		for addr in lookups[name]:
			outFile.write('%-40s %d IN A %s\n' % (
				name+'.', ttl, addr
			))

def writeOutputHosts(lookups, outFile=sys.stdout):
	for name in list(lookups.keys()):
		for addr in lookups[name]:
			outFile.write('%-20s %s\n' % (
				addr, name
			))

