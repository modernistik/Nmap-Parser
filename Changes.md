Revision history for Perl extension Nmap::Parser.

Bleeding Edge version: https://github.com/modernistik/Nmap-Parser

For a full list of changes and contributors see: https://github.com/modernistik/Nmap-Parser/commits/master

### Changes for 1.35
    - Updated build configuration thanks to @mperry2 (Pull #17)

### Changes for 1.34
    - Added devicetype thanks to @jcrochon (Pull #16)

### Changes for 1.33
    - Add tcp_port_state_ttl() function for export from nmap xml results. Thanks to @matrix.
    - Document fixes thanks to @zOrg1331

### Changes for 1.32
    - Updated website: https://github.com/modernistik/Nmap-Parser
    - Eliminate global variables %D - thanks to bonsaiviking
### Changes for 1.30
    - Merged features of pull request #6 (bonsaiviking)
        https://github.com/modernistik/Nmap-Parser/commit/7ccf752af
    - Allow osclass elements within osmatch, Nmap XML format changed in 6.00

### Changes for 1.21
    - Added support for hostscript and script tags
    - Changed ipv4_sort() to use a 10x faster sort method

### Changes for 1.20
	- Solved Issue 2: Host-specific start_time and end_time.
	- Applied Patch provided by briandlong on retrieving start_time and end_time attributes for host.
	- Solved Issue 6: \_del_port not removing port 0.
	- Thomas Equeter submitted patch to support traceroute in nmap output.

### Changes for 1.19
	- Added enhancement request by stevekatieterabyte for tcp_del_port and udp_del_port
	  (Thanks!). Modified the patch to work with a list of ports.
	- Added Robin Bowes' modification of nmap2sqlite as nmap2db to support MySQL (Thanks!)

### Changes for 1.16
	- Fixed minor bug in scanner.t where the number of tests to skip when nmap was not found was incorrect.
	- Repackaged to remove all the .\_* files from the package.
	- Fixed POD errors and added more documentation

### Changes for 1.14
	- Added cache_scan() to save the output of a parsescan() to a file before parsing.
	- Added new tests for servicefp fingerpriting and cache_scan().
	- Ran PerlTidy against module and other tools
	- Updated documentation

### Changes for 1.13
	- Added fingerprint() to Service object (thanks jpomiane)
	- Added documentation.

### Changes for 1.12
	- Added references to Google Code Project page.

### Changes for 1.11
	- Added parsing of distance information.
	- Fixed bug #1671876 on tcp_service() always returning null
	- Added ignoring of taskend,taskbegin and taskprogress information.
	- Added tests for nmap 4.20.
	- Changed lisence to MIT.

### Changes for 1.06
	- Added patch for new OS fingerprint (Thanks Okan Demirmen)
	- New os_fingerprint() method for Nmap::Parser::Host::OS
	- Updated documentation
	- Updated scan.pl to also read xml files (good for debugging)

### Changes for 1.05
	- Major speed improvements (less compile time)
	- Major reduction in unwanted memory usage
	- Redundant functions (or less used functions) are now created dynamically. (AUTOLOAD)
	- Documentation fixes

### Changes for 1.00
	- To see the changes, please read over the new documentation
		- Internal code is much (MUCH) cleaner and readable
		- removed 'ducttape' fixes and made stable & roubust changes
	- improved performance, removed unwanted code (legacy)
	- complete overhaul of internal code - new Framework
	- support for IPv6 addresses
	- data overwrite (overflow) protection
	- better support for multiple instances
	- fixed some minor bugs
	- process owner information obtained
	- all OS accuracy information obtained
	- some functions now take new parameters (more concise)
	- some functions renamed for clarity
	- new shortcut functions (for doing repetitive tasks easier)
	- Removed parsing filters (finally)
	- All indexes now start at 0 (not at 1).
	- Removed internal OS generic matching function since this is given by
		nmap now in the osclass tags
	- Removed the use of constants for indexes
	- Nmap::Parser::Host::Service object
		provides OO interface to service information for a given port
	- Nmap::Parser::Host::OS object
		provides OO interface to OS signature information for a given host
	- Nmap::Parser::Session replaces old Nmap::Parser::ScanInfo package
	- Nmap2SQLite security script included
	- removed old security tools
	- rewrote scan.pl (from scanhost.pl)
	- rewrote old tools to fit new framework
	- Fully updated documentation

### Changes for 0.80
	- Support for multiple instances of Nmap::Parser objects without overwriting data
	- All data (except filters) is are localized per object
	- The use of Storable (dclone) to correctly make duplicate of data structured
	- When filters are used to skip portinfo, all ports return state of 'closed'.
	- Nmap::Parser::XML no longer supported in distribution
		(you should change all calls to Nmap::Parser::XML to Nmap::Parser)

### Changes for 0.79
	- fixed ports that were declared as 'open|filtered'
		these now are counted as both 'open' and 'filtered'
		when using tcp_ports() and udp_ports().
	- sent a patch for XML::Twig in order to fix. It is now released in
		XML:Twig 3.16
	- added start_str() and time_str() : they return the human readable format
	of the scan start time and scan finish time (respectively).
	- updated for Nmap 3.81
	- documentation changes

### Changes for 0.78
	- updated documentation - now included tcp/udp service product
	- added new methods for new nmap command switch (-A)
		mac_addr, mac_vendor, ipv4_addr
	- verified xml format is still valid for nmap 3.55

### Changes for 0.77
	- updated documentation
	- added patches from Jeremy S.
	- tcp_service and udp_service tunnel, accuracy, confidence
	- os_accuracy method implemented
	- added ident/owner information

### Changes for 0.76
	- new module name: Nmap::Parser
	- leagcy file still ok to use for now: Nmap::Parser::XML
	- fixed problem using 'our' with older versions of perl
	- updated requirement for oldest usable version of XML::Twig => 3.11
	- you can extract owner information from running -I scanning
		tcp_service_owner and udp_service_owner

### Changes for 0.74
	- fixed ip address input bug
	- updated example scripts
	- fixed nmap not found bug
	- updated authorship informatin
	- raised verbose level to 2 in example scripts (help pages)
	- test script 4_scanner does not test. If nmap not installed
		it skips all tests.
	- updated tests
	- some example scripts read IP addresses from file
	- placed sourceforge image link on documentation
	- status_check is now called sweep
	- sweep.pl outputs active IP's to a file with a new command line switch
	- scan_host.pl is renamed to scanhost.pl
	- get_host_list,filter_by_osfamily, filter_by_status returns IP
		addresses in sorted IP order. ( uses sort_ips() )
	- sort_ips is a new function which will take a series of IPs and sort
		them correctly by comparing each quad in the address to each
		other.
	- example scripts use --randomize_hosts to be more stealthy
	- updated information on some example scripts because they require
		nmap 3.50+ for the version scanning.
	- updated parser tests, to check for sorted ip order

### Changes for 0.73
	- removed safe_* functions and placed them in the actual parsing
	functions. (I don't think they were never used.
	- updated BUG REPORT information

### Changes for 0.72
	- removed IGNORE_ADDPORTS constant
	- added contribution from Sebastian: nmap2csv.
	- edited the links to the sourceforge project site.
	- added parsescan() function to peroform quick nmap scans
	and parsing.
	- added more documentation
	- fixed some example scripts
	- added more tests for the new functionality

### Changes for 0.71
	- fixed a small bug in the installation under MSWin32 (PM_FILTER) which
	caused all tests to fail. (It was removing things that weren't comments.

### Changes for 0.70
	- updated changes from 0.69
	- updated documentation
	- fixed documentation bug of all the example scripts
	- updated examples script: they are more robust. Can either take
		the example file as input, or actually run scans.

### Changes for 0.69
	- new utility script : scan_host.pl
	- added EXAMPLES seciton in documentation
	- parses new 'version', 'extrainfo', and 'product'
		att from service tag (3.40+)
	- added \*\_service_version to \*::Host
	- added xml_version to \*::ScanInfo
	- more error prevention mechanisms
	- added os_osfamily, os_gen, os_vendor, os_type added
	- added OSINFO filter
	- ::ScanInfo::scan_types does not return number of scan types in scalar
		format. It will always return an array containing the scan
		types.
	- osfamily does not return the actual string (comma delimited), it always
	returns an array of os matches.
	- DEPRECATED: tcpsequence, ipidsequence, tcptssequence
		now use:
		tcpsequence_class, tcpsequence_values, tcpsequence_index
		ipidsequence_class, ipidsequence_values
		tcptssequence_class, tcptssequence_values


### Changes for 0.68
	- Licensing changes, now under GPL
	- added signatures for wireless access points (wap)
	- added os_match shortcut function
	- Problem with Makefile.PL, didn't pass correct dependencies.
	- tcp_port_state() and udp_port_state() return the state of the port
		when passed a port number.
	- Sorted port order when using tcp_ports and udp_ports
	- extraports tag parsing. It is also set up as a filter 'extraports'
		filtering. Added extraports_state and extraports_count to
		Nmap::Parser::Host class.
	- Added and fix some documentation
	- tcp_ports and udp_ports can take a parameter to filter what port list
		you wish to receive. It selects states based on port content
		state tag: filtered, closed, or open
		- previous versions (0.64 or earlier) of the parser, no arguments
	to tcp_ports and udp_ports would return the whole hashref of all the
	ports, this is now deprecated. Use the newly created functions
	tcp_service_name, tcp_service_proto, tcp_service_rpcnum,
	udp_service_name, udp_service_proto, and udp_service_rpcnum.
	- changed default filter for solaris to include 'sun' and not 'sunos'
	- more example scripts
	- no more wantarray usage for tcp_ports and udp_ports
	- more test cases

### Changes for 0.66
	- added short-cut function hostname() to return first hostname
	- added preliminary callback functionality (for registering events).
		This includes register_host_callback, and reset_host_callback
	- tcp_ports and udp_ports do not return hashref of all ports, only if
		passed a port number as an argument.The argument must be a port
		number. They default to returning an array of port numbers.
	- added short-cuts tcp_ports_count and udp_ports_count functions
	- added tcp_service_proto and udp_service_proto
	- added tcp_service_rpcnum and udp_service_rpcnum
	- POD fixes.
	- speed improvements

### Changes for 0.64
	- nmaprun filter bug fixed
	- important documentation changes

### Changes for 0.63
	- added vendor to os_class
	- fixed division by zero on one of the efficiency test.
	- it now checks to make sure Time::HiRes is installed before
		performing tests.
	- minor warning problems removed on Win32 systems.

### Changes for 0.62
	- stable release with all new changes.

### Changes for 0.6_4
	- changes to parse filter tags. All previously called PARSE_* have
		the PARSE_ removed from them. Ex: PARSE_OSFAMILY is now
		OSFAMILY.
	- osclass tag added.
	- a bug found with the sequences is fixed
	- making use of ignore_elts to save when creating objects
	- parse_filters completly excludes tags that you decide not to parse.
		Much faster parsing and memory usage efficiency. efficiency.t
		tests this benchmark to make sure that the twig parser does not
		do any work it doesn't have to.
	- permanently excluding some static tags using ignore_elts.
	- added SCANINFO filter.

### Changes for 0.60_3
	- os_port_used, now can return the open or closed port used in OS
		detection depending on the given parameter.

### Changes for 0.60_2
	- Bug #2968:
		fixed bogus 'use 5.008' in Makefile.PL (runs on 5.6 also)
		instead using 5.004
		fixed minor warnings when compiling with -w
		added 'use warnings' to \_methods test

### Changes for 0.60_1
	- fixed a bug with the test script (finding test file)
	- made a separate test to test the actual method existance
	- portability when running the tests using File::Spec.

### Changed for 0.60
	- better memory management using twig_roots
	- some bugs with output types and filters
	- generic_os and all references are now refereed to as 'osfamily'
		I thought it better resembles what it stands for.
	- fixed some documentation problems
	- parse_filter_* have been replaced with parse_filters(), which
		can enable multiple different filters through a hashref.
		Filters available:
		ONLY_ACTIVE, PARSE_OSFAMILY, PARSE_UPTIME, PARSE_PORTINFO,
		PARSE_SEQUENCES
	- added parse information of
		tcpsequence, ipidsequence, tcptssequence
	- additions to Nmap::Parser::Host methods
		tcpsequence, ipidsequence, tcptssequence

### Changes for 0.50
	- faster loading module
	- added more documentation
	- minor speed improvements
	- added methods to Nmap::Parser
		parse_filter_generic_os($bool) (see doc)
	- renamed only_active() to parse_filter_status($bool) (see doc)
	- Nmap::Parser::Host
		changed hostnames() to take a value a number (see doc)
		changed os_matches() to take a value a number (see doc)

### Changes for 0.40
	- added new package called ScanInfo (Nmap::Parser::ScanInfo
			this contains methods that make it easier to access the
			scan information
	- added new package called Host (Nmap::Parser::Host),
		which makes it easier to access values for each of the
		hosts found. See documentation.
		Host trees are now full of these \*::Host objects.
	- fixed minor bugs with parsing the xml files.
	- some memory usage improvements.

COPYRIGHT AND LICENSE

Copyright (C) 2003-2017 Anthony Persaud L<https://www.modernistik.com>

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
