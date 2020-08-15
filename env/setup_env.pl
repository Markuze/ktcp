#!/usr/bin/perl -w

use strict;
use threads;
use autodie;
use Regexp::Common qw /net number /;
use File::Basename;
use Getopt::Std;

my $key = 'MASTER_KEY';
die "NO such file $key\n" unless -e $key;
my $dir = dirname $0;
my $ssh = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $key ";
my @links = ();
my $sink = undef;
my $src = undef;
my %opts = ();

my $debug = "";

sub show_help {
	printf	"Example\n\$$0 -f <path to config file> [-r]\n";
	printf "-r : reboot the vms before installing\n";
	printf "-f : path to config file\n";
	printf "\tconfig file need co config one source one sink and at least one link\n";
	printf "\tExample;\n";
	printf "src <ip1> ";
	printf "link <ip2> ";
	printf "link <ip3> ";
	printf "sink <ip3>\n";
	die "\n";
}

sub reboot_vms {
	printf "rebooting $src\n";
	qx($ssh $src sudo reboot);
	printf "rebooting $sink\n";
	qx($ssh $sink sudo reboot);
	foreach (@links) {
		printf "rebooting $_\n";
		qx($ssh  $_ sudo reboot);
	}
	sleep (60);
}

sub parse_line {
	my $line = shift;
	if ($line =~ /sink\s+($RE{net}{IPv4})/) {
		die "sink defined twice\n" if(defined $sink);
		$sink = $1 if defined ($1);
	}
	if ($line =~ /src\s+($RE{net}{IPv4})/) {
		die "src defined twice\n" if(defined $src);
		$src = $1 if defined ($1);
	}
	while ($line =~ /link\s+($RE{net}{IPv4})/g) {
		push (@links,$1) if defined ($1);
	}
}

sub parse_config {
	my $config = shift;

	open (my $fh, "<", $config);
	while (<$fh>) {
		parse_line($_);
	}
}

sub create_tmux {
	printf " Config: $src -> $sink\n@links\n";
	open(my $fh, '>', "$dir/params.txt");
	print $fh "PANE_1=$src\nPANE_3=$sink\nPANE_0=$links[0]\nPANE_2=$links[$#links]\nKEY=$key\n";
	close $fh;
}

#Prepare edge
sub prep_edge {
	my ($sink, $src, $link) = @_;
	my $tid = threads->tid();
	open(my $fh, '>', "$dir/params_$tid.txt");
	print $fh "SINK=$sink\nNEXT=$link\nLOCAL=$src\n";
	close $fh;
	my $out = qx($dir/cp_files.sh $key $src $tid);
	printf("$ssh $src ~/ENV/setup_edge.sh\n");
	$out = qx($ssh $src ~/ENV/setup_edge.sh);
	qx(rm -rf "$dir/params_$tid.txt");
}

#Prepare LINKs
sub prep_link {
	my ($sink, $src, $prv, $local, $nxt) = @_;
	my $tid = threads->tid();
	open(my $fh, '>', "$dir/params_$tid.txt");
	print $fh "SINK=$sink\nNEXT=$nxt\nLOCAL=$local\n";
	print $fh "SRC=$src\nPREV=$prv\n";
	close $fh;
	my $out = qx($dir/cp_files.sh $key $local $tid);
	printf "config $local\nssh -i $key $local ~/ENV/setup_link.sh $debug\n";
	$out = qx($ssh $local ~/ENV/setup_link.sh $debug);
	print "$out\n";
	$out = qx($ssh $local ~/ENV/setup_ktcp.sh);
	qx(rm -rf "$dir/params_$tid.txt");
}


getopts('rdf:', \%opts);

$debug = "." if defined $opts{'d'};
show_help() unless (defined $opts{'f'});

parse_config $opts{'f'};

show_help() unless (defined $src && defined $sink && $#links >= 0);

create_tmux;

reboot_vms() if (defined($opts{'r'}));

threads->create(\&prep_edge, $sink, $src, $links[0]);
threads->create(\&prep_edge, $src, $sink, $links[$#links]);

push @links, $sink;
unshift @links, $src;

for (my $i=1; $i< $#links; $i++) {
	threads->create(\&prep_link, $sink, $src, $links[$i-1], $links[$i], $links[$i+1]);
}

foreach my $thr(threads->list()) {
	$thr->join();
}

