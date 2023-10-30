
import re
import logging

from .ianatlds import IANA_TLD_LIST

class StringFinder:

	re_dns = re.compile('([a-zA-Z0-9]{1}[-.a-zA-Z0-9]+)')
	re_windowend = re.compile('.*?([-.a-zA-Z0-9]+)$')

	def __init__(self, tlds=None, onlySuffixes=None):
		self.onlySuffixes=onlySuffixes
		if tlds!=None:
			self.tlds = tlds
		else:
			self.tlds = set(IANA_TLD_LIST)
		
		self.log = logging.getLogger('nmine.strfind')

	# called from searchString
	def divideString(self, s): 
	
		"""takes a string and returns a tuple of 3 strings (not, maybe,
		rest). not+maybe+rest = s. Up to two of (not,maybe,rest) can be ''. 
		not is text at the start of s which can't be a DNS name. maybe is a
		string in s which could be a dns name. rest is a substring after
		maybe which may or may not be a dns name (pass to divideString again
		to find out)."""
		
		mg = self.re_dns.search(s)
		if mg:
			notdns = s[0:mg.start()]
			maybedns = mg.group(1)
			rest = s[mg.end():]
			
			return (notdns, maybedns, rest)
		else:
			return (s, '', '')
	
	# called from searchStringConfirmed
	def searchString(self, s):
	
		"""return substrings in s that are could possibly be DNS names"""
	
		names = set()
		while True:
			(notdns, maybedns, rest) = self.divideString(s)
			
			if maybedns!='':
				names.add(maybedns)
			
			if rest=='':
				return names
			
			s = rest

	# MAIN ENTRY POINT
	def searchStringConfirmed(self, s):
		
		"""does the same as searchString, but only returns the subset of
		strings which have known TLD endings."""
		
		names = self.searchString(s)
		namesConfirmed = set()
		for name in names:
			if name.endswith('.'):
				name=name[:-1]
			
			name = name.lower()
			
			parts = name.split('.')
			if len(parts)>1 and parts[-1] in self.tlds and self.nameMatchesOnlySuffixes(name):
				namesConfirmed.add(name)

		return namesConfirmed

	def nameMatchesOnlySuffixes(self, name):
		if self.onlySuffixes==None:
			return True
		else:
			for suffix in self.onlySuffixes:
				if name.endswith(suffix.lower()):
					return True
			return False
						
