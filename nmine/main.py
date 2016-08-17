
import sys
import optparse
import logging

from strfind import StringFinder

def searchPath(path):
	f = open(path)
	sf = StringFinder()
	names = set()
	for line in f:
		for name in sf.searchStringConfirmed(line):
			names.add(name)
	
	for name in names:
		print ' *',name

def parseArgs(argv=sys.argv):
	
	parser = optparse.OptionParser(
		usage="%prog [-i <file>] <path> [<path> ...]",
		version="%prog v1.0"
	)
	parser.remove_option('--version')
	parser.add_option('-i', '--interesting', dest='scope', default=None, help= '''Path to file containing IPv4 addresses or prefixes which you consider "interesting" (the scope of the search).  This program will only output DNS names resolving to these addresses.  If not specified, a file named SCOPE in the current directory will be looked for and used if found.  Either a SCOPE file or this option is required.''')
	parser.add_option('-v', '--version', action='version', help='Display version number and exit')
	parser.add_option('-d', '--debug', action='store_true', default=False, help='Turn on debug logging output')
	
	(opts,args) = parser.parse_args(argv)
	
	searchItems = []
	if len(argv)>=2:
		searchItems = argv[1:]
	else:
		searchItems = ['.']

	return (searchItems, opts.scope, opts.debug)

def initLogging(debug):
	log = logging.getLogger('nmine')
	handler = logging.StreamHandler(sys.stderr)
	if debug:
		formatter = logging.Formatter('%(asctime)s %(name)s: %(message)s','%X')
	else:
		formatter = logging.Formatter('%(name)s: %(message)s')
	handler.setFormatter(formatter)
	log.addHandler(handler)
	if debug:
		log.setLevel(logging.DEBUG)
	else:
		log.setLevel(logging.ERROR)
	
class ScopeParseError(Exception):
	def __init__(self, scopePath, lineNum, errStr):
		self.scopePath = scopePath
		self.lineNum = lineNum
		self.errStr = errStr
	
	def __str__(self):
		return 'Error reading scope file %s on line %d: %s' % (
			self.scopePath,
			self.lineNum,
			self.errStr
		)
	
def loadScope(scopePath):
	log = logging.getLogger('nmine')

	scope = []

	if scopePath==None:
		scopePath='SCOPE'

	log.debug('loading scope %s' % scopePath)

	import iptree

	lineNum=1
	for line in open(scopePath):
		line = line.strip()
		try:
			p = iptree.Prefix(line)
		except ValueError, ve:
			raise ScopeParseError(scopePath, lineNum, str(ve))
		else:
			scope.append(p)
		lineNum+=1
	
	return scope
	
def main():
	
	(searchItems, scopePath, debug) = parseArgs()
	
	initLogging(debug)
	log = logging.getLogger('nmine')

	try:
		import iptree
	except ImportError:
		log.error("You don't seem to have the iptree Python module installed. See https://github.com/xelphene/iptree.")
		raise SystemExit(1)

	try:
		import dns.resolver
	except ImportError:
		log.error("You don't seem to have dnspython installed. See http://www.dnspython.org. (On Ubuntu/Debian: apt-get install python-dnspython)")
		raise SystemExit(1)

	try:
		scope = loadScope(scopePath)
	except IOError, ioe:
		log.error('Error loading scope file %s: %s. Try the -i <path> command line option.' % (ioe.filename, str(ioe)))
		raise SystemExit(1)
	except ScopeParseError, spe:
		log.error(spe)
		raise SystemExit(1)
	
	if debug:
		for s in scope:
			log.debug('scope item: %s' % s)

	# TODO: build a list of paths to every file we will search for DNS names
	# TODO: add options for which DNS resolver to use.
		