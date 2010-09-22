#!/usr/bin/perl -w
# Instant messenging sniffer

use strict;
use warnings;
use nfqueue;
use POSIX;
use Date::Format;
use File::Spec;
use File::Pid;
use Log::Dispatch;
use NetPacket::IP qw(IP_PROTO_TCP);
use NetPacket::TCP;


my $daemon = "imsniff";
my $version = "0.1b";

my $logging = 1;			# 1 - logging is on
my $logFilePath = "/var/log/";		# log file path
my $logFile = $logFilePath . $daemonName . ".log";
my $pidFilePath = "/var/run/";		# pid file path
my $pidFile = $pidFilePath . $daemonName . ".pid";

my $dieNow = 0;				# used for "infinte loop" construct

sub getOptions {
    my (@ARGV) = @_;
    my $arg;
    if (scalar(@ARGV) > 0 && $ARGV[0]=~/-c=(.*)/) {
	my $configfile = $1;
	open(CONFIG,$configfile) || die "Error opening config file.\n";
	while(<CONFIG>) {
	    $arg=@_;
	    if ($arg!~/^\#/) {
		$nodb = 1 if ($arg=~/nodb/);
		$daemonMode = 1 if ($arg=~/daemon/);
		$logFile = $1 if ($arg=~/logfile=(.*)/);
		$pidFile = $1 if ($arg=~/pidfile=(.*)/);
	    }
	}
	close(CONFIG);
    } else {
	foreach $arg (@ARGV) {
	    $nodb = 1 if ($arg=~/--nodb/);
	    $daemonMode = 1 if ($arg=~/--daemon/);
	    $logFile = $1 if ($arg=~/--logfile=(.*)/);
	    $pidFile = $1 if ($arg=~/--pidfile=(.*)/);
	    $dumpFile = $1 if ($arg=~/--dumpfile=(.*)/);
	    if ($arg=~/--h/ or $arg=~/-h/) {
		print "Instant messenging sniffer $ver\n";
		print "to use:\n";
		print "\t-c=filename - get imsniff options from a config file\n";
		exit;
	    }
	}
    }
    $daemonMode = 0 if ($dumpFile);
    return 1;
}



print "Instant messenging sniffer $ver\n";
print "developed by Denis Klester aka dini\n";

&getOptions(@ARGV) || die "Could no get options\n";



# start logging
my $sub = sub { my %p = @_; return reverse $p{message}; };
my $log = new Log::Dispatch( callbakss => $sub );
$log->add( Log::Dispatch::File->new( name => $daemon, min_level => 'info', mode => 'append', filename  => $logFile ));
$log->warning("Starting sniffer $daemon version $version");

# daemonize
use POSIX qw(setsid);
chdir '/';
umask 0;
open STDIN, '/dev/null' || die "Can't read /dev/null: $!";
open STDOUT, '>>/dev/null' || die "Can't write to /dev/null: $!";
open STDERR, '>>/dev/null' || die "Can't write to /dev/null: $!";
defined( my $pid = fork ) || die "Can't fork: $!";
exit if $pid;

# dissociate this process from the controlling terminal that
# started it and stop being part of whatever process group
# this process was a part of.
POSIX::setsid() || die "Can't start a new session.";

# Callback signal handler for signals.
$SIG{INT} = $SIG{TERM} = $SIG{HUP} = \&signalHandler;
$SIG{PIPE} = 'ignore';

# create pid file
my $pidfile = File::Pid->new( { file => $pidFile, } );
$pidfile->write || die "Can't write PID file: $!";

# turn on logging
if ($logging) { open LOG, ">>$logFile"; }

# "infinite" loop where some useful process happens
until ($dieNow) {
    sleep(120);
    logEntry("log something");
}

sub logEntry {
    my ($logText) = @_;
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
    my $dateTime = sprintf "%4d-%02d-%02d %02d:%02d:%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec;
    if ($logging) {
	print LOG "$dateTime $logText\n";
    }
}

sub signalHandler {
    $dieNow = 1;		# this will cause the "infinite loop" to exit
}

# do this stuff when exit() is called.
END {
    if ($logging) { close LOG }
    $pidfile->remove;
}
