#!/usr/bin/perl

use strict;
use warnings;

use IO::Socket::UNIX;
use IO::Socket;

use Data::Dumper;

use constant DEBUG => 1;

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
	Peer       => "/var/run/p0f/p0f.sock",
        Type      => SOCK_STREAM,
        Timeout   => 10) or die $@;

my @ip = (192.168.175.140);
my $query = pack('L L C A16', P0F_QUERY_MAGIC, P0F_CMD_QUERY_HOST, P0F_ADDR_IPV4, @ip);
print Dumper $query if DEBUG;
syswrite($client, $query, 25);

my $header;
sysread($client, $header, 8);
print Dumper $header if DEBUG;
my ($magic, $status) = unpack('L L', $header);

if ($magic != P0F_RESP_MAGIC) {
	$client->shutdown(2);
	die "Bad response magic";
}
if ($status == 0x20) {
	$client->shutdown(2);
	die "No host match";
}
if ($status != 0x10) {
	$client->shutdown(2);
	die "No status OK";
}

my $payload;
my $chunkSize = 16 + 1 + 7*4 + 2 + 1 + 1 + 32*6;
sysread($client, $payload, $chunkSize);
print Dumper $payload if DEBUG;

$client->shutdown(2);

my (	$addr,
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
	$language) = unpack("A16 C L L L L L L L s C C A32 A32 A32 A32 A32 A32", $payload);

my ($addr1, $addr2, $addr3, $addr4) = unpack('C4', $addr);
$addr = "$addr1.$addr2.$addr3.$addr4";

print "Address:         '$addr'\n";
print "Address type:    '$addrType'\n";
print "OS name:         '$osName'\n";
print "OS flavour:      '$osFlavour'\n";
print "HTTP name:       '$httpName'\n";
print "HTTP Flavour:    '$httpFlavour'\n";
print "Link type:       '$linkType'\n";
print "Language:        '$language'\n";
