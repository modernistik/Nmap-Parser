#!/usr/bin/perl

use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 15;
use Nmap::Parser;

use constant TEST_FILE => 'nmap_results.xml';
use constant HOST1     => '127.0.0.1';
use constant HOST2     => '127.0.0.2';
use constant HOST3     => '127.0.0.3';
use constant HOST4     => '127.0.0.4';

use constant TOTAL_ADDRS => 4;
use vars qw($FH $TOTAL @UP_HOSTS @DOWN_HOSTS);

$FH = File::Spec->catfile( cwd(), 't', TEST_FILE );
$FH = File::Spec->catfile( cwd(), TEST_FILE ) unless ( -e $FH );

my $np = new Nmap::Parser;
isa_ok( $np, 'Nmap::Parser' );

ok( $np->callback( \&my_callback ), 'Registering callback function' );
is( $np->callback(), 0, 'Unregistering callback function' );
ok( $np->callback( \&my_callback ), 're-registering callback function' );

$TOTAL = 0;

$np->parsefile($FH);

is( $TOTAL, TOTAL_ADDRS, 'Making sure all hosts were parsed in callback' );
ok( eq_set( [@UP_HOSTS], [ HOST1, HOST3, HOST4 ] ),
    'Testing for correct UP hosts' );
ok( eq_set( [@DOWN_HOSTS], [HOST2] ), 'Testing for correct DOWN hosts' );

for my $host ( HOST1, HOST2, HOST3, HOST4 ) {
    is( $np->get_host($host), undef,
        'Making sure ' . $host . ' does not exists' );
}

sub my_callback {
    my $host = shift;
    my $addr = $host->addr;

    if ( $addr =~ /^127\.0\.0/ ) {
        $TOTAL++;
    }

    isa_ok( $host, 'Nmap::Parser::Host', $host->addr );
    if    ( $host->status eq 'up' )   { push @UP_HOSTS,   $addr; }
    elsif ( $host->status eq 'down' ) { push @DOWN_HOSTS, $addr; }

}
