#!/usr/bin/perl

use strict;
use warnings;

use IO::Socket::UNIX;
use IO::Socket;

use Data::Dumper;

use constant DEBUG => 0;

use constant P0F_QUERY_MAGIC      => 0x50304601;
use constant P0F_RESP_MAGIC       => 0x50304602;
use constant P0F_STATUS_BADQUERY  => 0x00;
use constant P0F_STATUS_OK        => 0x10;
use constant P0F_STATUS_NOMATCH   => 0x20;
use constant P0F_ADDR_IPV4        => 0x04;
use constant P0F_ADDR_IPV6        => 0x06;
use constant P0F_MATCH_FUZZY      => 0x01;
use constant P0F_MATCH_GENERIC    => 0x02;
use constant P0F_CMD_QUERY_HOST   => 0x01;
use constant P0F_CMD_QUERY_CACHE  => 0x02;

my $client = new IO::Socket::UNIX(
    Peer    => "/var/run/p0f/p0f.sock",
    Type    => SOCK_STREAM,
    Timeout => 10) or die $@;

my @ip = qw( 192 168 55 0);
my $query = pack('L L C C16', P0F_QUERY_MAGIC, P0F_CMD_QUERY_CACHE, P0F_ADDR_IPV4, @ip);
$query .= pack ('C', 24);
print Dumper unpack ('H*', $query);
syswrite($client, $query, 26);

my $header;
sysread($client, $header, 8);
print Dumper $header if DEBUG;
my ($magic, $status) = unpack('L L', $header);

if ($magic != P0F_RESP_MAGIC) {
	$client->shutdown(2);
	die "Bad response magic";
}
if ($status != 0x10) {
	$client->shutdown(2);
	die "No status OK";
}

my $count;
sysread($client, $count, 4);

$count = unpack('L', $count);
print "Count: $count\n";

exit 0 unless ($count > 0);

my $payload;
my $chunkSize = 16 + 1 + 7*4 + 2 + 1 + 1 + 32*6;
sysread($client, $payload, $chunkSize * $count);
print Dumper $payload if DEBUG;

$client->shutdown(2);

my $offset = 0;
for (my $i = 0; $i < $count; $i++) {
	my ($addr,
	    $addrType,
	    $firstSeen,
	    $lastSeen,
	    $totalConn,
	    $uptimeMinutes,
	    $uptimeDays,
	    $lastNAT,
	    $lastOSChange,
	    $distance,
	    $badSW,
	    $matchQuality,
	    $osName,
	    $osFlavour,
	    $httpName,
	    $httpFlavour,
	    $linkType,
	    $language) = unpack("@" ."$offset" . "(A16 C L L L L L L L s C C A32 A32 A32 A32 A32 A32)", $payload);
	$offset += $chunkSize;

	my ($addr1, $addr2, $addr3, $addr4) = unpack('C4', $addr);
        $addr1 = '0' unless defined $addr1;
        $addr2 = '0' unless defined $addr2;
        $addr3 = '0' unless defined $addr3;
        $addr4 = '0' unless defined $addr4;
	$addr = "$addr1.$addr2.$addr3.$addr4";

	print "Address:         '$addr'\n";
	print "Address type:    '$addrType'\n";
	print "OS name:         '$osName'\n";
	print "OS flavour:      '$osFlavour'\n";
	print "HTTP name:       '$httpName'\n";
	print "HTTP Flavour:    '$httpFlavour'\n";
	print "Link type:       '$linkType'\n";
	print "Language:        '$language'\n";
	print "\n";
}
