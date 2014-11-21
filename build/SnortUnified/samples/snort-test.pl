#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use SnortUnified::MetaData(qw(:ALL));


$debug = 1;

my $sids = get_snort_sids("/usr/snort/rules/sid-msg.map","/usr/snort/rules/gen-msg.map");
my $class = get_snort_classifications("/usr/snort/rules/classification.config");

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
    print($i++);;
    foreach $field ( @{$record->{'FIELDS'}} ) {
        if ( $field ne 'pkt' ) {
            print("," . $record->{$field});
        }
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
