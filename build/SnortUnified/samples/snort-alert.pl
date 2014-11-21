#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use SnortUnified::MetaData(qw(:ALL));
use SnortUnified::TextOutput(qw(:ALL));

use Data::Dumper;

$debug = 0;

my $sids = get_snort_sids("/Download/Snort/snort-2.8.3.1/etc/sid-msg.map","/Download/Snort/snort-2.8.3.1/etc/gen-msg.map");
my $class = get_snort_classifications("/Download/Snort/snort-2.8.3.1/etc/classification.config");

my $file = shift;
my $openfile;
my $uf_file = undef;
my $old_uf_file = undef;
my $record = undef;
my $i = 0;

$uf_file = get_latest_file() || die "no files to get";

$openfile = openSnortUnified($uf_file) || die "cannot open $uf_file";

while (1) {

  $old_uf_file = $uf_file;
  $uf_file = get_latest_file() || die "no files to get";

  if ( $old_uf_file ne $uf_file ) {
    closeSnortUnified();
    $openfile = openSnortUnified($uf_file) || die "cannot open $uf_file";
  }

  read_records();
}

sub read_records() {
  while ( $record = readSnortUnifiedRecord() ) {
    print Dumper($record) if $debug;
    if ( $openfile->{'TYPE'} eq 'LOG' ) {
        print_log($record, $sids, $class);
    } elsif ($openfile->{'TYPE'} eq 'ALERT' ) {
        print_alert($record, $sids, $class);
    } elsif ($openfile->{'TYPE'} eq 'UNIFIED2' ) {
        if ( $record->{'TYPE'} eq $UNIFIED2_PACKET ) {
            # Unified2 textoutput of packets seems broken, I need samples
            # if ( $event_id == $record->{'event_id'} ) {
            #     print_log($record, $sids, $class);
            # }
        } elsif ( $record->{'TYPE'} eq $UNIFIED2_IDS_EVENT ) {
            print_alert($record, $sids, $class);
        } else {
            # not handled
        }
    } else {
       # Not handles
    }
    print("\n");
  }
  return 0;
}

sub get_latest_file() {
  my @ls = <$file*>;
  my $len = @ls;
  my $uf_file = "";

  if ($len) {
  # Get the most recent file
    my @tmparray = sort{$b cmp $a}(@ls);
    $uf_file = shift(@tmparray);
  } else {
    $uf_file = undef;
  }
  return $uf_file;
}
