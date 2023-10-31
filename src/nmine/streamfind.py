
import re
from .ianatlds import IANA_TLD_LIST

class StreamFinder:
	
	endings = ['.'+tld for tld in IANA_TLD_LIST]
	re_dns = re.compile('([-.a-zA-Z0-9]+)')
	re_windowend = re.compile('.*?([-.a-zA-Z0-9]+)$')

	blacklist = ('document.do','asp.net')

	def __init__(self):
		self.pos=0
		self._buf = ''
		self.extraTLDprovider = lambda: set()

	def updateTLDs(self):
		print('NEW TLDs')
		pass

	@classmethod
	def tokenizeString(cls, s):
		sf = cls()
		sf.feed(s)
		print('wsr:',cls.searchWindow(s))
		#return s

		"""exhaustively check self._buf until there's no hope for finding
		any DNS names in it."""
		
		#assert False
		rv=[]
		
		while True:
			#print 'buffer check round:',repr(self._buf)
			(name, newbuf) = cls.searchWindow(self._buf)
			print('got name=%s newbuf=%s' % (repr(name),repr(newbuf)))
			if name!=None:
				#yield name
				rv += {'type':'dns', 'value':name}
			elif name==None:
				pass
				
			if newbuf==self._buf:
				return
			self._buf = newbuf

	@classmethod	
	def searchWindow(cls, s):
	
		"""search for a DNS name in the buffer. If one is found, return the
		DNS name and the REST of the input string. If one is not found,
		return any ending of the input string the could possibly be the
		start of a DNS name if more data were appended."""
	
		#for i in range(0,len(self._buf)):
		mg = cls.re_dns.search(s)
		if mg:
			start = mg.start()
			end = mg.end()
			#word = self._buf[start:end]
			word = mg.group(1)
			
			#print 'possibility:',repr(word)
			for ending in cls.endings or ending in ['.'+tld for tld in self.extraTLDprovider]:
				if word.lower().endswith(ending) and word.lower()!=ending and word.lower() not in cls.blacklist:
					#print 'NAME:',word
					return (s[0:start], word, s[end:])
			
			# if we had a possibility but it isn't real, AND it goes
			# all the way to the end of the string, then preserve the ending
			if end==len(s):
				return ('',None, s)
			else:	
				return (s[0:start], None, s[end:])
		else:
			mg = cls.re_windowend.match(s)			
			if mg:
				#return (s[0:len(mg.group(1)], None, mg.group(1))
				pass
			else:
				#print 'window end match failure:',repr(s)
				return (s, None, '')
	
	def checkBuffer(self):

		"""exhaustively check self._buf until there's no hope for finding
		any DNS names in it."""
		
		while True:
			###Bprint 'buffer check round:',repr(self._buf)
			(start, name, newbuf) = self.__class__.searchWindow(self._buf)
			###print 'got name=%s newbuf=%s' % (repr(name),repr(newbuf))
			if name:
				yield name
			if newbuf==self._buf:
				return
			self._buf = newbuf
	
	def feed(self, chunk):
		self._buf += chunk
		for name in self.checkBuffer():
			yield name
	
	def searchPath(self, path):
		f=file(path)
	
	@classmethod
	def searchFile(cls, f):
		sf = cls()
		chunk = f.read(1024)
		while chunk:
			for name in sf.feed(chunk):
				yield name
			chunk = f.read(1024)
	
	@classmethod
	def searchPath(cls, path):
		f=file(path)
		return cls.searchFile(f)
	
	@classmethod
	def searchDir(cls, path):
		for (dirpath, drnames, filenames) in os.walk(path):
			for filename in filenames:
				path = os.path.join(dirpath,filename)
				#print 'checking',path
				for name in cls.searchPath(path):
					yield name
					
				
				
