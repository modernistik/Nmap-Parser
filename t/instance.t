#!/usr/bin/perl

use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 12;
use Nmap::Parser;
use constant HOST1     => '127.0.0.1';
use constant HOST2     => '127.0.0.2';
use constant HOST3     => '127.0.0.3';
use constant HOST4     => '127.0.0.4';
use constant BASE_FILE => 'instance.xml';
use constant CURR_FILE => 'nmap_results.xml';

use vars qw($base $curr $BASE $CURR);

$BASE = File::Spec->catfile( cwd(), 't', BASE_FILE );
$BASE = File::Spec->catfile( cwd(), BASE_FILE ) unless ( -e $BASE );

$CURR = File::Spec->catfile( cwd(), 't', CURR_FILE );
$CURR = File::Spec->catfile( cwd(), CURR_FILE ) unless ( -e $CURR );

$curr = new Nmap::Parser;
$base = new Nmap::Parser;

isa_ok( $curr, 'Nmap::Parser' );
isa_ok( $base, 'Nmap::Parser' );

ok( $base->parsefile($BASE), 'Parsing from nmap data base image file' );
ok( $curr->parsefile($CURR), 'Parsing from nmap data current image file' );

my $host_curr = $curr->get_host(HOST3);
my $host_base = $base->get_host(HOST3);

isa_ok( $host_curr, 'Nmap::Parser::Host', 'host_curr' );
isa_ok( $host_base, 'Nmap::Parser::Host', 'host_base' );

cmp_ok( $host_curr->tcp_port_count, '!=', $host_base->tcp_port_count,
    'Object instance difference: TCP COUNT' );
cmp_ok( $host_curr->udp_port_count, '!=', $host_base->udp_port_count,
    'Object instance difference: UDP COUNT' );

my %port = ();
my @diff_open =
  grep { $port{$_} < 2 }
  ( map { $port{$_}++; $_ }
      ( $host_curr->tcp_open_ports, $host_base->tcp_open_ports ) );
is( scalar @diff_open, 2, "Open port difference: " . ( join '', @diff_open ) );

my @diff_filtered =
  grep { $port{$_} < 2 }
  ( map { $port{$_}++; $_ }
      ( $host_curr->tcp_filtered_ports, $host_base->tcp_filtered_ports ) );
is( scalar @diff_filtered,
    1, "Filtered port difference: " . ( join '', @diff_filtered ) );

is( $base->get_host(HOST2), undef, 'Base image should not have ' . HOST2 );
isnt( $curr->get_host(HOST2), undef, 'Current image should have  ' . HOST2 );
