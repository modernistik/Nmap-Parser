#!/usr/bin/perl

use strict;
use blib;
use Nmap::Parser;
use File::Spec;
use Cwd;
use Test::More tests => 173;

use constant HOST1 => '127.0.0.1';
use constant HOST2 => '127.0.0.2';
use constant HOST3 => '127.0.0.3';
use constant HOST4 => '127.0.0.4';
my @UP_HOSTS = ( HOST1, HOST3, HOST4 );
my @DOWN_HOSTS = (HOST2);
use constant TOTAL_HOSTS => 4;

use constant TEST_FILE => 'nmap_results.xml';
use vars qw($host $np $session $svc $os $FH);

$FH = File::Spec->catfile( cwd(), 't', TEST_FILE );
$FH = File::Spec->catfile( cwd(), TEST_FILE ) unless ( -e $FH );

my $np = new Nmap::Parser;

parser_test();
session_test();
host_1();
host_2();
host_3();
host_4();

sub parser_test {
    ok( $np->parsefile($FH), "Parsing nmap data: $FH" );

    #TESTING GET_IPS()
    is_deeply(
        [ $np->get_ips() ],
        [ HOST1, HOST2, HOST3, HOST4 ],
        'Testing get_ips for correct number of hosts'
    );
    is_deeply(
        [ $np->get_ips('up') ],
        [ HOST1, HOST3, HOST4 ],
        'Testing get_ips for correct hosts with status = up'
    );
    is_deeply( [ $np->get_ips('down') ],
        [HOST2], 'Testing get_ips for correct hosts for with status = down' );

    #TESTING IPV4_SORT
    my @hosts = ( HOST3, HOST1, HOST4, HOST2 );
    is_deeply(
        [ $np->ipv4_sort(@hosts) ],
        [ HOST1, HOST2, HOST3, HOST4 ],
        'Testing ipv4_sort'
    );

    #TESTING ALL_HOSTS()
    my $total_hosts = 0;
    for my $h ( $np->all_hosts() ) {
        isa_ok( $h, 'Nmap::Parser::Host' );
        isnt( $h->status, undef,
            'Testing host object ' . $h->addr . ' in all_hosts()' );
        $total_hosts++;
    }

    is( $total_hosts, TOTAL_HOSTS,
        "Testing correct number of hosts with all_hosts()" );

    #TESTING ALL_HOSTS(UP)
    my $total_uphosts = 0;
    for my $h ( $np->all_hosts('up') ) {
        isnt( $h->addr, HOST2,
            'Testing host ' . $h->addr . ' in all_hosts(up)' );
        $total_uphosts++;
    }

    is( $total_uphosts, scalar(@UP_HOSTS),
        "Testing correct number of UP hosts with all_hosts(up)" );

    #TESTING ALL_HOSTS(DOWN)
    my $total_downhosts = 0;
    for my $h ( $np->all_hosts('down') ) {
        is( $h->addr, HOST2, 'Testing host ' . $h->addr . ' in all_hosts(up)' );
        $total_downhosts++;
    }

    is( $total_downhosts, scalar(@DOWN_HOSTS),
        "Testing correct number of DOWN hosts with all_hosts(down)" );

}

sub session_test {

    isa_ok( $session = $np->get_session(), 'Nmap::Parser::Session' );
    is(
        $session->numservices(),
        1023 + 1023,
        'Session: total number of services'
    );
    is( $session->numservices('connect'),
        1023, 'Session: numservices type = connect' );
    is( $session->numservices('udp'), 1023, 'Session: numservices type = udp' );
    is( $session->start_time(), 1057088883, 'Session: start_time' );
    is(
        $session->start_str(),
        'Tue Jul  1 14:48:03 2003',
        'Session: start_str'
    );
    is( $session->finish_time(), 1057088900, 'Session: finish_time' );
    is( $session->time_str(), 'Tue Jul  1 14:48:20 2003', 'Session: time_str' );
    is( $session->nmap_version(), '3.80', 'Session: nmap_version' );
    is( $session->xml_version(),  '1.01', 'Session: xml_version' );
    is(
        $session->scan_args(),
        'nmap -v -v -v -oX test.xml -O -sTUR -p 1-1023 127.0.0.[1-4]',
        'Session: scan_args'
    );
    is( $session->scan_type_proto(), undef, 'Session: scan_type_proto()' );
    is( $session->scan_type_proto('connect'),
        'tcp', 'Session: scan_type_proto(connect)' );
    is( $session->scan_type_proto('udp'),
        'udp', 'Session: scan_type_proto(udp)' );

}

sub host_1 {

    isa_ok( $host = $np->get_host(HOST1), 'Nmap::Parser::Host',
        'GET ' . HOST1 );
    is( $host->status,      'up',                'Host1: status' );
    is( $host->addr,        HOST1,               'Host1: addr' );
    is( $host->addrtype,    'ipv4',              'Host1: addrtype' );
    is( $host->ipv4_addr,   HOST1,               'Host1: ipv4_addr' );
    is( $host->mac_addr,    '00:09:5B:3F:7D:5E', 'Host1: mac_addr' );
    is( $host->mac_vendor,  'Netgear',           'Host1: mac_vendor' );
    is( $host->hostname,    'host1',             'Host1: hostname()' );
    is( $host->hostname(0), $host->hostname,     'Host1: hostname(0)' );
    is( $host->hostname(1), 'host1_2',           'Host1: hostname(1)' );
    is_deeply(
        [ $host->all_hostnames() ],
        [ 'host1', 'host1_2' ],
        'Host1: all_hostnames'
    );

    #Testing Port Information
    is( $host->extraports_state(), 'closed', 'Host1: extraports_state' );
    is( $host->extraports_count(), 2038,     'Host1: extraports_count' );

    is( $host->tcp_port_count(), 8, 'Host1: tcp_port_count' );
    is( $host->udp_port_count(), 2, 'Host1: udp_port_count' );

    is_deeply(
        [ $host->tcp_ports() ],
        [qw(22 25 80 111 443 555 631 4903)],
        'Host1: tcp_ports()'
    );
    is_deeply(
        [ $host->tcp_ports('open') ],
        [qw(80 111 443 555 631)],
        'Host1: tcp_ports(open)'
    );
    is_deeply( [ $host->tcp_ports('closed') ],
        [qw(4903)], 'Host1: tcp_ports(closed)' );
    is_deeply( [ $host->tcp_ports('filtered') ],
        [qw(22 25 555)], 'Host1: tcp_ports(filtered)' );
    is_deeply( [ $host->tcp_ports('open|filtered') ],
        [qw(555)], 'Host1: tcp_ports(open|filtered)' );
    is_deeply( [ $host->udp_ports() ], [qw(111 937)], 'Host1: udp_ports()' );
    is_deeply( [ $host->udp_ports('open') ],
        [qw(111)], 'Host1: udp_ports(open)' );
    is_deeply( [ $host->udp_ports('filtered') ],
        [qw(937)], 'Host1: udp_ports(filtered)' );
    is_deeply( [ $host->udp_ports('closed') ],
        [qw()], 'Host1: udp_ports(closed)' );

    is( $host->tcp_ports('open'),
        $host->tcp_open_ports(), 'Host1: tcp_open_ports' );
    is(
        $host->tcp_ports('filtered'),
        $host->tcp_filtered_ports(),
        'Host1: tcp_filtered_ports'
    );
    is(
        $host->tcp_ports('closed'),
        $host->tcp_closed_ports(),
        'Host1: tcp_closed_ports'
    );

    is( $host->udp_ports('open'),
        $host->udp_open_ports(), 'Host1: udp_open_ports' );
    is(
        $host->udp_ports('filtered'),
        $host->udp_filtered_ports(),
        'Host1: udp_filtered_ports'
    );
    is(
        $host->udp_ports('closed'),
        $host->udp_closed_ports(),
        'Host1: udp_closed_ports'
    );

    $host->tcp_del_ports('80');

    is_deeply( [ $host->tcp_ports('open') ],
        [qw(111 443 555 631)],
        'Host1: tcp_del_ports(80) (should not be open)' );

    $host->tcp_del_ports( 111, 443 );
    is_deeply( [ $host->tcp_ports('open') ],
        [qw(555 631)], 'Host1: tcp_del_ports(111,443) (should not be open)' );

    is_deeply( [ $host->tcp_ports() ],
        [qw(22 25 555 631 4903)],
        'Host1: tcp_ports() after deleting 80,111,443' );

    is( $host->uptime_seconds(), '1973', 'Host1: uptime_seconds' );
    is(
        $host->uptime_lastboot(),
        'Tue Jul  1 14:15:27 2003',
        'Host1: uptime_lastboot'
    );

    is( $host->tcpsequence_index(), 4336320, 'Host1: tcpsequence_index' );
    is(
        $host->tcpsequence_class(),
        'random positive increments',
        'Host1: tcpsequence_class'
    );
    is(
        $host->tcpsequence_values(),
        'B742FEAF,B673A3F0,B6B42D41,B6C710A1,B6F23FC4,B72FA3A8',
        'Host1: tcpsequence_values'
    );

    is( $host->ipidsequence_class(), 'All zeros', 'Host1: ipidsequence_class' );
    is( $host->ipidsequence_values(),
        '0,0,0,0,0,0', 'Host1: ipidsequence_values' );

    is( $host->tcptssequence_class(), '100HZ', 'Host1: tcptssequence_class' );
    is(
        $host->tcptssequence_values(),
        '30299,302A5,302B1,302BD,302C9,302D5',
        'Host1: tcptssequence_values'
    );
    is( $host->distance(), 1, 'Host1: distance = 1' );

    isa_ok( $np->del_host(HOST1), 'Nmap::Parser::Host', 'DEL ' . HOST1 );
    is( $np->get_host(HOST1), undef, 'Testing deletion of ' . HOST1 );

    #TESTING SERVICE OBJECT FOR HOST 1
    my $svc;
    isa_ok( $svc = $host->tcp_service(22),
        'Nmap::Parser::Host::Service', 'TCP port 22' );
    is( $svc->name,       'ssh',   'Service: name' );
    is( $svc->method,     'table', 'Service: method' );
    is( $svc->confidence, 3,       'Service: confidence' );

    isa_ok( $svc = $host->udp_service(111),
        'Nmap::Parser::Host::Service', 'UDP port 111' );
    is( $svc->name,   'rpcbind', 'Service: name' );
    is( $svc->proto,  'rpc',     'Service: proto' );
    is( $svc->rpcnum, '100000',  'Service: rpcnum' );

    #TESTING OS OBJECT FOR HOST 1
    my $os;
    my $fingerprint =
" SEQ(SP=C5%GCD=1%ISR=C7%TI=Z%II=I%TS=8) ECN(R=Y%DF=Y%T=40%W=16D0%O=M5B4NNSNW2%CC=N%Q=) T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=) T2(R=N) T3(R=Y%DF=Y%T=40%W=16A0%S=O%A=S+%F=AS%O=M5B4ST11NW2%RD=0%Q=) T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=) T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=) U1(R=Y%DF=N%T=40%TOS=C0%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUL=G%RUD=G) IE(R=Y%DFI=N%T=40%TOSI=S%CD=S%SI=S%DLI=S) ";
    isa_ok( $os = $host->os_sig(), 'Nmap::Parser::Host::OS', 'os_sig()' );
    is( $os->os_fingerprint(), $fingerprint, 'HOST1: os_fingerprint()' );

    #TESTING NON-EXISTENT TRACE FOR HOST1
    ok( !$host->all_trace_hops(), 'Host1 has no trace information' );

    #TESTING NON-EXISTENT HOSTSCRIPT FOR HOST1
    ok( !$host->hostscripts(), 'Host1 has no hostscript information' );
}

sub host_2 {
    isa_ok( $host = $np->get_host(HOST2), 'Nmap::Parser::Host',
        'GET ' . HOST2 );
    is( $host->addr,   HOST2,  'Host2: addr' );
    is( $host->status, 'down', 'Host2: status = down' );
    isa_ok( $np->del_host(HOST2), 'Nmap::Parser::Host', 'DEL ' . HOST2 );
    is( $np->get_host(HOST2), undef, 'Testing deletion of ' . HOST2 );

}

sub host_3 {
    isa_ok( $host = $np->get_host(HOST3), 'Nmap::Parser::Host',
        'GET ' . HOST3 );

    #TESTING SERVICE OBJECTS
    my $svc;

    isa_ok(
        $svc = $host->tcp_service(22),
        'Nmap::Parser::Host::Service',
        'tcp_service(22) for ' . HOST3
    );
    is( $svc->owner,     'root',          'TCP Service: owner' );
    is( $svc->name,      'ssh',           'TCP Service: name' );
    is( $svc->product,   'OpenSSH',       'TCP Service: product' );
    is( $svc->version,   '3.4p1',         'TCP Service: version' );
    is( $svc->extrainfo, 'protocol 1.99', 'TCP Service: extrainfo' );
    is_deeply( [ $svc->scripts() ], [ 'ssh-hostkey' ], 'Port has scripts' );
    {
        my $output = $svc->scripts('ssh-hostkey');
        like( $output, qr/^1024 e8:2.*RSA\)$/s, 'Script output ok');
    }

    isa_ok(
        $svc = $host->udp_service(80),
        'Nmap::Parser::Host::Service',
        'udp_service(780) for ' . HOST3
    );
    is( $svc->owner,     'www-data',                'UDP Service: owner' );
    is( $svc->name,      'http',                    'UDP Service: name' );
    is( $svc->product,   'Apache httpd',            'UDP Service: product' );
    is( $svc->version,   '1.3.26',                  'UDP Service: version' );
    is( $svc->extrainfo, '(Unix) Debian GNU/Linux', 'UDP Service: extrainfo' );

    my $servicefp =
'SF-Port25-TCP:V=3.48%D=11/5%Time=3FA9032C%r(NULL,57,"220\x20s0002\.berger\.com\x20ESMTP\x20Oracle\x20Email\x20Server\x20SMTP\x20Inbound\x20Server\t9\.0\.4\.0\.0\x20\t\x20\x20Ready\r\n")%r(Help,17D,"220\x20s0002\.berger\.com\x20ESMTP\x20Oracle\x20Email\x20Server\x20SMTP\x20Inbound\x20Server\t9\.0\.4\.0\.0\x20\t\x20\x20Ready\r\n214-2\.3\.0\x20This\x20is\x20Oracle\x20eMail\x20SMTP\x20Server\n214-2\.3\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20HELO\x20\x20\x20\x20EHLO\x20\x20\x20\x20MAIL\x20\x20\x20\x20RCPT\x20\x20\x20\x20DATA\n214-2\.3\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20RSET\x20\x20\x20\x20NOOP\x20\x20\x20\x20QUIT\x20\x20\x20\x20HELP\x20\x20\x20\x20DSN\n214-2\.3\.0\x20For\x20more\x20info\x20use\x20\"HELP\x20<topic>\"\.\n214-2\.3\.0\x20For\x20local\x20information\x20send\x20email\x20to\x20Postmaster\x20at\x20your\x20site\.\n214\x202\.3\.0\x20End\x20of\x20HELP\x20info\n");';
    isa_ok(
        $svc = $host->tcp_service(25),
        'Nmap::Parser::Host::Service',
        'tcp_service(25) for ' . HOST3
    );
    is( $svc->fingerprint(), $servicefp,
        'Verifying correct servicefp parsing on tcp_service(25) for ' . HOST3 );

    $servicefp =
'SF-Port21-TCP:V=3.48%D=11/5%Time=3FA9032C%r(NULL,32,"220\x20Oracle\x20Internet\x20File\x20System\x20FTP\x20Server\x20ready\r\n")%r(GenericLines,53,"220\x20Oracle\x20Internet\x20File\x20System\x20FTP\x20Server\x20ready\r\n200\x20Connection\x20closed,\x20good\x20bye\r\n")%r(Help,57,"220\x20Oracle\x20Internet\x20File\x20System\x20FTP\x20Server\x20ready\r\n500\x20HELP:\x20command\x20not\x20understood\.\r\n");';
    isa_ok(
        $svc = $host->tcp_service(953),
        'Nmap::Parser::Host::Service',
        'tcp_service(953) for ' . HOST3
    );
    is( $svc->fingerprint(), $servicefp,
        'Verifying correct servicefp parsing on tcp_service(953) for '
          . HOST3 );

    isa_ok( $svc = $host->tcp_service(500),
        'Nmap::Parser::Host::Service',
        'Verifying good reference returned on unscanned port service (500)' );

    isa_ok( $np->del_host(HOST3), 'Nmap::Parser::Host', 'DEL ' . HOST3 );
    is( $np->get_host(HOST3), undef, 'Testing deletion of ' . HOST3 );

    #TESTING TRACE FOR HOST3
    my $hops_count = $host->all_trace_hops();
    is( $hops_count, 2, 'Host3 has trace information' );
    is( $host->trace_error(), 'Error', 'Host3 trace is in error' );

    #TESTING HOSTSCRIPT FOR HOST3
    is_deeply(
        [ $host->hostscripts() ],
        [ 'nbstat' ],
        'Host3 has one hostscript' );
    {
        my $output = $host->hostscripts('nbstat');
        is( substr($output,0,16), "\n  NetBIOS name:",
            'Host3 hostscript correct' );
    }

}

sub host_4 {
    isa_ok( $host = $np->get_host(HOST4), 'Nmap::Parser::Host',
        'GET ' . HOST4 );
    my $os;

    #TESTING OS OBJECTS
    isa_ok(
        $os = $host->os_sig,
        'Nmap::Parser::Host::OS',
        'os_sig for ' . HOST4
    );
    is( $os->portused_open,   22, 'OS: portused open' );
    is( $os->portused_closed, 1,  'OS: portused closed' );
    is( $os->name_count,      2,  'OS: name count' );

    is( $os->name,    'Linux Kernel 2.4.0 - 2.5.20', 'OS: name()' );
    is( $os->name(0), $os->name,                     'OS: name(0)' );
    is( $os->name(1), 'Solaris 9',                   'OS: name(1)' );
    is_deeply(
        [ $os->all_names ],
        [ 'Linux Kernel 2.4.0 - 2.5.20', 'Solaris 9' ],
        'OS: all_names'
    );
    is( $os->name_accuracy(),  100,                  'OS: name_accuracy()' );
    is( $os->name_accuracy(0), $os->name_accuracy(), 'OS: name_accuracy(0)' );
    is( $os->name_accuracy(1), 99,                   'OS: name_accuracy(1)' );

    my $count = 11;
    is( $os->class_count(), $count, 'OS: class_count MAX = ' . $count );

    is( $os->osfamily(),       'AOS',           'OS: osfamily()' );
    is( $os->osfamily(0),      $os->osfamily(), 'OS: osfamily(0)' );
    is( $os->osfamily($count), 'Linux',         'OS: osfamily(MAX)' );
    is( $os->osfamily(15), $os->osfamily($count),
        'OS: osfamily(15) = osfamily(MAX)' );

    is( $os->vendor(),       'Redback',     'OS: vendor()' );
    is( $os->vendor(0),      $os->vendor(), 'OS: vendor(0)' );
    is( $os->vendor($count), 'Linux',       'OS: vendor(MAX)' );
    is( $os->vendor(15), $os->vendor($count), 'OS: vendor(15) = vendor(MAX)' );

    is( $os->osgen(),       undef,              'OS: osgen()' );
    is( $os->osgen(0),      $os->osgen(),       'OS: osgen(0)' );
    is( $os->osgen($count), '2.4.x',            'OS: osgen(MAX)' );
    is( $os->osgen(15),     $os->osgen($count), 'OS: osgen(15) = osgen(MAX)' );

    is( $os->type(),       'router',          'OS: type()' );
    is( $os->type(0),      $os->type(),       'OS: type(0)' );
    is( $os->type($count), 'general purpose', 'OS: type(MAX)' );
    is( $os->type(15),     $os->type($count), 'OS: type(15) = type(MAX)' );

    is( $os->class_accuracy(), 97, 'OS: class_accuracy()' );
    is( $os->class_accuracy(0), $os->class_accuracy(),
        'OS: class_accuracy(0)' );
    is( $os->class_accuracy($count), 50, 'OS: class_accuracy(MAX)' );
    is(
        $os->class_accuracy(15),
        $os->class_accuracy($count),
        'OS: class_accuracy(15) = type(MAX)'
    );

    my $fingerprint =
" SCAN(V=4.20%D=6/11%OT=22%CT=%CU=%PV=N%DS=1%G=N%M=001321%TM=466DE2F1%P=i686-pc-windows-windows) T5(Resp=Y%DF=Y%W=0%ACK=S++%Flags=AR%Ops=) T6(Resp=Y%DF=Y%W=0%ACK=O%Flags=R%Ops=) T7(Resp=Y%DF=Y%W=0%ACK=S++%Flags=AR%Ops=) PU(Resp=Y%DF=N%TOS=C0%IPLEN=164%RIPTL=148%RID=E%RIPCK=E%UCK=E%ULEN=134%DAT=E) ";
    isa_ok( $os = $host->os_sig(), 'Nmap::Parser::Host::OS', 'os_sig()' );
    is( $os->os_fingerprint(), $fingerprint, 'HOST4: os_fingerprint()' );

    is( $host->tcptssequence_values, undef,
        'HOST4: tcptssequence_values = undef' );
    is( $host->distance(), 10, 'Host4: distance = 10' );

    isa_ok( $np->del_host(HOST4), 'Nmap::Parser::Host', 'DEL ' . HOST4 );
    is( $np->get_host(HOST4), undef, 'Testing deletion of ' . HOST4 );

    #TESTING TRACE FOR HOST4
    my @hops = $host->all_trace_hops();
    ok( !$host->trace_error(), 'Host4 trace is not in error' );
    is( $host->trace_port(), 80, 'Host4 trace port information' );
    is( $host->trace_proto(), 'tcp', 'Host4 trace proto information' );
    is( ( scalar @hops ), 3, 'Host4 trace size' );

    is( $hops[0]->ttl(), 1, 'Host4 hop1 TTL' );
    ok( !$hops[0]->rtt(), 'Host4 hop1 has no RTT' );
    is( $hops[0]->ipaddr(), '192.168.1.1', 'Host4 hop1 IP address' );
    ok( !$hops[0]->host(), 'Host4 hop1 has no hostname' );

    is( $hops[2]->ttl(), 4, 'Host4 hop4 TTL' );
    is( $hops[2]->rtt(), 26.48, 'Host4 hop4 RTT' );
    is( $hops[2]->ipaddr(), '1.1.1.1', 'Host4 hop4 IP address' );
    is( $hops[2]->host(), 'www.straton-it.fr', 'Host4 hop4 hostname' );

}
