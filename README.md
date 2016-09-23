# nmine

nmine searches files for substrings that appear to be valid DNS names. It
resolves them and outputs the result if the address it resolves to is of
interest.

# Examples / Description

Let's say you have some arbitrary file (or directories of files) containing
DNS names of some sort:

```
> ls
blah.txt
> cat blah.txt 
nothing 
The quick brown fox yahoo.com jumps over the lazy dog. hurricanelabs.com]
Lorem ipsum dolor sit amet, ex wisi elitr eruditi pro.   129831; asdf
google.com!zzzhomero has ei
;sad0uf23 www.github.com 090
```

You're interested in any names which resolve to any address in 192.0.0.0/8.
You put this in a file called "SCOPE" (or any file specified with the -i
option):

```
>> cat > SCOPE
192.0.0.0/8
```

You then run nmine while in the above directory, and any names resolving to
your network(s) of interest are output:

```
> nmine
hurricanelabs.com.                       600 IN A 192.230.81.48
www.github.com.                          600 IN A 192.30.253.112
```

# Options

* -i (filename): Name of a file containing IPv4 networks of interest.

* -n (address): Name or address of a DNS server to send all queries to.

* -f hosts|zone: Output format. "zone" is like BIND zone files or dig
output.  "hosts" is like /etc/hosts.

* -t (TLD): Specify additional TLDs to consider valid. May be specified
multiple times.

* -T: Do NOT automatically consider IANA TLDs valid. The only TLDs
considered valid will be those specified with -t.

# Copyright and License

Copyright (C) 2016 Hurricane Labs

nmine was written by Steve Benson for Hurricane Labs.

nmine is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 3, or (at your option) any later
version.

nmine is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with
this program; see the file LICENSE.  If not, see <http://www.gnu.org/licenses/>.
