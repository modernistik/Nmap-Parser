#!/usr/bin/perl
#  THIS IS A MODIFIED VERSION OF NMAP2SQLITE SCRIPT ORIGINALLY DEVELOPED BY ANTHONY G PERSAUD
#  BUT MODIFIED TO WORK WITH MYSQL DATABASES BY ROBIN BOWES.  
#  nmap2db.pl
#  Description:
#  	It takes in a nmap xml file and stores it into a SQLite database using DBI for
#   searching, storing and better reporting. This is just an example of how an
#   IP network database can be created using Nmap-Parser and automation.
# 
#
#  MIT License
#  
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#  
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#  
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#  THE SOFTWARE.
#  


use strict;
use DBI;
use Nmap::Parser 1.00;
use vars qw(%S %G);
use File::Spec::Functions;
use Pod::Usage;
use Carp;

#Will use in the future
use Getopt::Long;
Getopt::Long::Configure('bundling');

GetOptions(
    'help|h|?' => \$G{helpme},
    'nmap=s'   => \$G{nmap},
    'xml'      => \$G{file},
    'scan'     => \$G{scan},
    'dbhost=s' => \$G{DBHOST},
    'db=s'     => \$G{DBNAME},
    'dbtype=s' => \$G{DBTYPE},
    'table=s'  => \$G{TABLE},
    'dbuser=s' => \$G{DBUSER},
    'dbpass=s' => \$G{DBPASS},
) or ( pod2usage( -exitstatus => 0, -verbose => 2 ) );
unless ( $G{file} || $G{scan} ) {
    pod2usage( -exitstatus => 0, -verbose => 2 );
}

print "\n$0 - ( http://nmapparser.wordpress.com )\n", ( '-' x 50 ), "\n\n";

if ( $G{scan} && $G{nmap} eq '' ) {
    $G{nmap} = find_exe();
}

$G{DBNAME} ||= 'ip.db';
$G{TABLE}  ||= 'hosts';
$G{DBTYPE} ||= 'SQLite';
if ( $G{DBTYPE} eq 'mysql' ) {
    $G{DBHOST} ||= 'localhost';
}

print "Using DATABASE : $G{DBNAME}\n";
print "Database type  : $G{DBTYPE}\n";
if ( $G{DBTYPE} eq 'mysql' ) {
    print "Using host     : $G{DBHOST}\n";
    print "Using user     : $G{DBUSER}\n" if $G{DBUSER};
}
print "Using TABLE    : $G{TABLE}\n";
print "Using NMAP_EXE : $G{nmap}\n" if ( $G{scan} );

#Schema for table, simple for now
$S{CREATE_TABLE} = qq{  CREATE TABLE } . $G{TABLE} . qq{ (
  ip              VARCHAR(15) PRIMARY KEY NOT NULL,
  mac             VARCHAR(17),
  status          VARCHAR(7) DEFAULT 'down',
  hostname        TEXT,
  open_ports      TEXT,
  filtered_ports  TEXT,
  osname	      TEXT,
  osfamily        TEXT,
  osgen           TEXT,
  last_scanned    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (ip))
  };

$S{INSERT_HOST}
    = qq{REPLACE INTO }
    . $G{TABLE}
    . qq{ (ip, mac, status, hostname, open_ports, filtered_ports, osname, osfamily, osgen) VALUES (?,?,?,?,?,?,?,?,?)};

my $np = new Nmap::Parser;

$np->callback( \&insert_host );

#not implemented in this script, will finish later... ;-)
#$np->parsescan($PATH_TO_NMAP, $NMAP_ARGS, @IPS);

# Set up the DB connection
my $dsn = "DBI:$G{DBTYPE}";
$dsn .= ":host=$G{DBHOST}" if $G{DBTYPE} eq 'mysql';
$dsn .= ":$G{DBNAME}";

my $dbh = eval { DBI->connect( $dsn, $G{DBUSER}, $G{DBPASS} ) };
croak $@ if ($@);

# Check if table exists...

if ( !table_exists( $dbh, $G{DBNAME}, $G{TABLE} ) ) {
    print "\nGenerating table: $G{TABLE} ...\n";
    eval { $dbh->do( $S{CREATE_TABLE} ) };
    croak $@ if ($@);
}

#do stuff
my $sth_ins = eval { $dbh->prepare_cached( $S{INSERT_HOST} ) };
croak $@ if ($@);

#for every host scanned, insert or updated it in the table
if ( $G{file} ) {
    for my $file (@ARGV) {
        print "\nProcessing file $file...\n";
        $np->parsefile($file);
    }
}
elsif ( $G{scan} && $G{nmap} ) {
    print "\nProcessing scan: "
        . $G{nmap}
        . ' -sT -O -F '
        . join( ' ', @ARGV );
    $np->parsescan( $G{nmap}, '-sT -O -F', @ARGV );
}

#Booyah!
$sth_ins->finish;
$dbh->disconnect();

#This function will insert the host, or update it if it already exists
#Of course, we can always check the last_scanned entry in the database to
#make sure the latest information is there, but this is just beta version.
sub insert_host {
    my $host = shift;
    my $os   = $host->os_sig();

    #ip, mac, status, hostname, open_ports, filtered_ports, os_family, os_gen
    my @input_values = (
        $host->addr,
        $host->mac_addr || undef,
        $host->status   || undef,
        $host->hostname || undef,
        join( ',', $host->tcp_open_ports )     || undef,
        join( ',', $host->tcp_filtered_ports ) || undef,
        $os->name     || undef,
        $os->osfamily || undef,
        $os->osgen    || undef
    );

    my $rv
        = $sth_ins->execute(@input_values) ? "ok" : "OOPS! - " . DBI->errstr;

    printf( "\t..> %-15s : (%4s) : %-s\n", $host->addr, $host->status, $rv );

}

sub find_exe {

    my $exe_to_find = 'nmap';
    $exe_to_find =~ s/\.exe//;
    local ($_);
    local (*DIR);

    for my $dir ( File::Spec->path() ) {
        opendir( DIR, $dir ) || next;
        my @files = ( readdir(DIR) );
        closedir(DIR);

        my $path;
        for my $file (@files) {
            $file =~ s/\.exe$//;
            next unless ( $file eq $exe_to_find );

            $path = File::Spec->catfile( $dir, $file );
            next unless -r $path && ( -x _ || -l _ );

            return $path;
            last DIR;
        }
    }

    warn
        "[Nmap2SQLite] No nmap in your PATH: use '--nmap nmap_path' option\n";
    exit;

}

sub table_exists {
    my ( $dbh, $dbname, $tblname ) = @_;
    my @names = eval { $dbh->tables( '', $dbname, $tblname, "TABLE" ) };
    croak $@ if ($@);
    my %names_h;
    @names_h{@names} = ();
    my $sql_quote_char = $dbh->get_info(29);
    return (
        exists( $names_h{ $sql_quote_char . $tblname . $sql_quote_char } ) );
}

__END__

=pod

=head1 NAME

nmap2db - store nmap scan data into entries in SQLite/MySQL database

=head1 SYNOPSIS

 nmap2db.pl [options] --xml  <XML_FILE> [<XML_FILE> ...]
 nmap2db.pl [options] --scan <IP_ADDR>  [<IP_ADDR> ...]

Examples connecting to a MySQL database (Robin Bowes):

 nmap2db.pl --dbtype mysql --dbname netdb --dbuser netuser --dbpass secret --xml 192.168.25.0.xml


=head1 DESCRIPTION

This script uses the nmap security scanner with the Nmap::Parser module
in order to take an xml output scan file from nmap (-oX option), and place the information
into a SQLite database (ip.db), into table (hosts).

This is a modified version of the nmap2sqlite.pl script written originally by Anthony Persaud
but modified by Robin Bowes to support MySQL databases.

Here is the schema for the table stored in the SQLite database

  ip              TEXT       PRIMARY  KEY NOT NULL,
  mac             TEXT,
  status          TEXT,
  hostname        TEXT,
  open_ports      TEXT,
  filtered_ports  TEXT,
  osname          TEXT,
  osfamily        TEXT,
  osgen           TEXT,
  last_scanned    TIMESTAMP  DEFAULT  CURRENT_TIMESTAMP,
  UNIQUE (ip))

=head1 OPTIONS

These options are passed as command line parameters. Please use EITHER --scan or --xml. NOT both. 

=over 4

=item B<--dbhost DBHOST>

Connect to the DB on server DBHOST.

Default: localhost.

=item B<--db DBNAME>

Sets the database name to DBNAME.

Default: ip.db

=item B<--dbtype DBTYPE>

Sets the type of databases to use. Currently supported values are: mysql, SQLite

Default: SQLite

=item B<--table TABLE_NAME>

Sets the table name to use in the database as TABLE_NAME. 

Default: hosts

=item B<--dbuser DBUSER>

Connect to the database as user DBUSER.

Default: current user

=item B<--dbpass DBPASS>

Connect to the database with password DBPASS

Default: no password

=item B<-h,--help,-?>

Shows this help information.

=item B<--nmap>

The path to the nmap executable. This should be used if nmap is not on your path.

=item B<--scan>

This will use parsescan() for the scan and take the arguments as IP addreses.

=item B<--xml>

This will use parsefile() for the input and take the arguments as nmap scan xml files.

=back 4

=head1 TARGET SPECIFICATION

This documentation was taken from the nmap man page. The IP address inputs
to this scripts should be in the nmap target specification format.

The  simplest  case is listing single hostnames or IP addresses onthe command
line. If you want to scan a subnet of  IP addresses, you can append '/mask' to
the hostname or IP address. mask must be between 0 (scan the whole internet) and
 32 (scan the single host specified). Use /24 to scan a class 'C' address and
 /16 for a class 'B'.

You can use a more powerful notation which lets you specify an IP address
using lists/ranges for each element. Thus you can scan the whole class 'B'
network 128.210.*.* by specifying '128.210.*.*' or '128.210.0-255.0-255' or
even use the mask notation: '128.210.0.0/16'. These are all equivalent.
If you use asterisks ('*'), remember that most shells require you to escape
them with  back  slashes or protect them with quotes.

Another interesting thing to do is slice the Internet the other way.

Examples:

 nmap2db.pl --scan 127.0.0.1
 nmap2db.pl --scan target.example.com
 nmap2db.pl --scan target.example.com/24
 nmap2db.pl --scan 10.210.*.1-127
 nmap2db.pl --scan *.*.2.3-5
 nmap2db.pl --scan 10.[10-15].10.[2-254]
  
Examples connecting to a MySQL database:

 nmap2db.pl --dbtype mysql --dbname netdb --dbuser netuser --dbpass secret --xml 192.168.25.0.xml

=head1 OUTPUT EXAMPLE

See the SQLite database that is created. Default ip.db

=head1 SUPPORT

=head2 Discussion Forum

If you have questions about how to use the module, or any of its features, you
can post messages to the Nmap::Parser module forum on CPAN::Forum.
L<http://www.cpanforum.com/dist/Nmap-Parser>

=head2 Bug Reports

Please submit any bugs to:
L<https://github.com/apersaud/Nmap-Parser/issues>

B<Please make sure that you submit the xml-output file of the scan which you are having
trouble.> This can be done by running your scan with the I<-oX filename.xml> nmap switch.
Please remove any important IP addresses for security reasons.

=head2 Feature Requests

Please submit any requests to:
L<https://github.com/apersaud/Nmap-Parser/issues>


=head1 SEE ALSO

L<Nmap::Parser>

The Nmap::Parser page can be found at: L<https://github.com/apersaud/Nmap-Parser>.
It contains the latest developments on the module. The nmap security scanner
homepage can be found at: L<http://www.insecure.org/nmap/>.

=head1 AUTHOR

Anthony Persaud <apersaud[at]gmail.com> L<http://modernistik.com>

Additional features and improvements by:
Robin Bowes <robin[at]robinbowes.com> L<http://robinbowes.com>
Daniel Miller L<http://bonsaiviking.com/>

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

L<http://www.opensource.org/licenses/gpl-license.php>

=cut
