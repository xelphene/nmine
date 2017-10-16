
import sys
import os
import optparse
import logging

from strfind import StringFinder
from output import writeOutputZone
from output import writeOutputHosts
from ianatlds import IANA_TLD_LIST

def extractNamesFromPath(path, tlds, onlySuffixes=None):
	'''given a path to a file, extract all possible DNS names from it.'''
	f = open(path)
	sf=  StringFinder(tlds=tlds, onlySuffixes=onlySuffixes)
	names = set()
	for line in f:
		for name in sf.searchStringConfirmed(line):
			names.add(name)
	return names		

def parseArgs(argv=sys.argv):
	
	parser = optparse.OptionParser(
		usage="%prog [-i <file>] <path> [<path> ...]",
		version="%prog v1.0"
	)
	parser.remove_option('--version')
	parser.add_option('-i', '--interesting',
		dest='scope',
		default=None,
		help= '''Path to file containing IPv4 addresses or prefixes which you consider "interesting" (the scope of the search).  This program will only output DNS names resolving to these addresses.  If not specified, a file named SCOPE in the current directory will be looked for and used if found.  Either a SCOPE file or this option is required.''')
	parser.add_option('-n', '--nameserver',
		dest='nameserver',
		default=None,
		help= 'Nameserver to query. The normal DNS servers for this system will be used by default.')
	parser.add_option('-f', '--format',
		dest='format',
		default='zone',
		help='Output format. Must be either "hosts" (/etc/hosts style) or "zone" (BIND zone file / dig output style).')
	parser.add_option('-v', '--version',
		action='version',
		help='Display version number and exit')
	parser.add_option('-d', '--debug',
		action='store_true',
		default=False,
		help='Turn on debug logging output' )
	parser.add_option('-t', '--addtld',
		action='append',
		dest='addTlds',
		default=[],
		type='str',
		help='Specify additional TLDs to consider valid. May be specified multiple times.')
	parser.add_option('-T', '--noianatlds',
		action='store_false',
		dest='useIanaTlds',
		default=True,
		help='Do NOT automatically consider IANA TLDs valid. The only TLDs considered valid will be those specified with -t.')
	parser.add_option('-s','--onlysuffix',
		action='append',
		dest='onlySuffixes',
		default=[],
		type='str',
		help='Only consider names with this ending to be valid names at all. May be specified multiple times.')
			
	(opts,args) = parser.parse_args(argv)

	searchItems = []
	if len(args)>=2:
		searchItems = args[1:]
	else:
		searchItems = ['.']

	if opts.format not in ('zone','hosts'):
		sys.stderr.write('Invalid value for -f/--format option. It must be "zone" or "hosts".\n')
		raise SystemExit(1)

	return (searchItems, opts)

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

	lineNum=0
	for line in open(scopePath):
		lineNum+=1
		
		parts = line.split('#')
		line = parts[0]
		line = line.strip()
		
		if line=='':
			continue
		
		try:
			p = iptree.Prefix(line)
		except ValueError, ve:
			raise ScopeParseError(scopePath, lineNum, str(ve))
		else:
			scope.append(p)
	
	return scope

class BadSearchPath(Exception):
	def __init__(self, searchPath):
		self.searchPath = searchPath

class NonExistentSearchPath(BadSearchPath):
	def __str__(self):
		return 'search path %s does not exist' % repr(self.searchPath)

class InvalidSearchPath(BadSearchPath):
	def __str__(self):
		return 'search path %s is neither a file nor a directory.' % repr(self.searchPath)

def buildSearchFiles(searchPaths, doDotFiles=False):
	log = logging.getLogger('nmine')
	searchFiles = []
	for searchPath in searchPaths:
		if not os.path.exists(searchPath):
			raise NonExistentSearchPath(searchPath)
		else:
			if os.path.isfile(searchPath):
				log.debug('will search file %s' % searchPath)
				searchFiles.append(searchPath)
			elif os.path.isdir(searchPath):
				log.debug('recursively searching directory %s for files to search' % searchPath)
				for (dirpath, dirnames, filenames) in os.walk(searchPath, topdown=True):
					if not doDotFiles:
						for dirname in dirnames:
							if dirname.startswith('.'):
								del dirnames[dirnames.index(dirname)]
						filenames = filter(lambda f: not f.startswith('.'), filenames)
					for filename in filenames:		
						sf = os.path.join(dirpath, filename)
						log.debug('will search file %s' % sf)
						searchFiles.append(sf)
			else:
				raise InvalidSearchPath(searchPath)
	return searchFiles

def resolveNames(names, scope, nameserver=None):
	import dns.resolver
	import iptree
	log = logging.getLogger('nmine')
	
	results = {}
	
	if nameserver==None:
		# use the normal system DNS servers
		r = dns.resolver.Resolver(configure=True)
	else:
		# use the specified DNS server, not the system ones
		r = dns.resolver.Resolver(configure=False)
		r.nameservers = [nameserver]

	for name in names:
		log.debug('looking up %s ...' % name)
		try:
			answer = r.query(name,'A')
		except dns.resolver.NoNameservers:
			pass
		except dns.resolver.NXDOMAIN:
			pass
		except dns.resolver.NoAnswer:
			pass
		except dns.exception.Timeout:
			pass
		except dns.name.EmptyLabel:
			# raised if ".." is in a name. parser shouldn't even return that. TODO
			pass
		else:
			for rdata in answer:
				log.debug('resolved %s to %s' % (name, rdata.address))
				prefix = iptree.Prefix(rdata.address)
				for scopeEntry in scope:
					log.debug('    %s in %s ?' % (prefix, scopeEntry))
					if prefix in scopeEntry or prefix==scopeEntry:
						log.debug('        HIT: %s' % rdata.address)
						if results.has_key(name):
							results[name].append(rdata.address)
						else:
							results[name] = [rdata.address]
	return results

def main():
	
	(searchPaths, opts) = parseArgs()
	scopePath = opts.scope
	debug = opts.debug
	initLogging(debug)
	log = logging.getLogger('nmine')

	###################################################
	# make sure required python modules are available in a user-friendly
	# manner
	###################################################

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

	###################################################
	# load the scope
	###################################################

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

	###################################################
	# build up a list of TLDs to consider valid
	###################################################
	
	tlds = []
	if opts.useIanaTlds:
		tlds += IANA_TLD_LIST
	for tld in opts.addTlds:
		tlds.append( tld )
	log.debug('TLD list:')
	for tld in tlds:
		log.debug('    %s' % tld)
	log.debug('END TLD list')
	tlds = set(tlds)

	###################################################
	# build up a list of general suffixes to consider valid
	###################################################
	
	onlySuffixes=None
	if len(opts.onlySuffixes)>0:
		onlySuffixes = opts.onlySuffixes
		log.debug('onlySuffixes enabled: %s' % ', '.join(onlySuffixes))
	else:
		log.debug('onlySuffixes disabled. Any name ending with a known TLD considered valid.')

	###################################################
	# build up a list of paths of plain files to extract possible names from
	###################################################

	log.debug('search paths: %s' % repr(searchPaths))
	try:
		searchFiles = buildSearchFiles(searchPaths)
	except BadSearchPath, bsp:
		log.error(bsp)
		raise SystemExit(1)
	
	###################################################
	# extract possible DNS names from the files discovered above
	###################################################
	
	allNames = set()
	for searchFile in searchFiles:
		log.debug('*** extracting names from %s' % searchFile)
		names = extractNamesFromPath(searchFile, tlds, onlySuffixes)
		for name in names:
			log.debug('    %s found in %s' % (name, searchFile))
		allNames = allNames.union(names)
	log.debug('extraction complete. possible names found:')
	for name in allNames:
		log.debug('    %s' % name)

	###################################################
	# actually resolve the names
	###################################################
	
	lookups = resolveNames(allNames, scope, nameserver=opts.nameserver)
	
	if opts.format=='hosts':
		writeOutputHosts(lookups)
	else:
		writeOutputZone(lookups)
