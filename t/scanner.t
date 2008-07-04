#!/usr/bin/perl

use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 8;
use constant IP      => '127.0.0.1';

use Nmap::Parser;

my $np = new Nmap::Parser;

can_ok( $np, 'cache_scan' );
can_ok( $np, 'parsescan' );
my $nmap_path = find_nmap();

SKIP: {
    skip '[Nmap-Parser] Could not find nmap executable in path', 6
      if ( $nmap_path eq '' );
    ok( $nmap_path, "Exe Path: $nmap_path" );
    
	skip "[Nmap-Parser] No self scanning with MSWin32", 4
      if ( $^O eq 'MSWin32' || $^O =~ /cygwin/ );
    ok(
        $np->parsescan( $nmap_path, '-p 1-80', IP ),
        'Running parsescan against ' . IP
    );

	#if everything passed we can do another scan using the new cache_scan() function
    skip
"[Nmap-Parser] Current user does not have read/write permissions in this directory.",
      3
      unless ( -w '.' && -r '.' );

    my $cache_file = 'cache.' . ( rand(10000) % 10000 ) . '.xml';
    $np->cache_scan($cache_file);
    ok(
        $np->parsescan( $nmap_path, '-p 1-80', IP ),
        'Running parsescan /w cache enabled against ' . IP
    );
    ok( -s $cache_file, 'Testing if cache file was created and written' );
    ok( $np->parsefile($cache_file),
        'Verifying cache file is nmap xml compatible.' );
    is( unlink($cache_file), 1, 'Unlinking created cache file' );

}

sub find_nmap {
	#I think I borrowed this from someone (or from a Cookbook)
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

            #  Should symbolic link be considered?  Helps me on cygwin but ...
            next unless -r $path && ( -x _ || -l _ );

            return $path;
            last DIR;
        }
    }

}
