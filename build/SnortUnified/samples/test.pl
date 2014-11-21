#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use Data::Dumper;
use Socket;

$file = shift;
$debug = 0;
$UF_Data = {};
$record = {};

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

while (1) {
    read_records();
}

closeSnortUnified();
return 0;

sub read_records() {
  while ( $record = readSnortUnifiedRecord() ) {

#    print Dumper($record);

    print "record type " . $record->{'TYPE'} . " is " . $UNIFIED2_TYPES->{$record->{'TYPE'}} . "\n";
    # next unless $record->{'TYPE'} eq $UNIFIED2_EVENT;
    # next unless $record->{'TYPE'} eq $UNIFIED2_IDS_EVENT
    # next unless $record->{'TYPE'} eq $UNIFIED2_IDS_EVENT_VLAN;
    # next unless $record->{'TYPE'} eq $UNIFIED2_IDS_EVENT_IPV6_VLAN;
    next unless $record->{'TYPE'} eq $UNIFIED2_EXTRA_DATA;

    print Dumper($record);
    
    foreach $field ( @{$record->{'FIELDS'}} ) {
        if ( $field ne 'pkt' && $field ne 'data_blob' ) {
            print("Field " . $field . " : " . $record->{$field} . "\n");
        } else {
            print("data_blob:\n");
            print("==================== ASCII\n");
            print make_ascii($record->{'data_blob'}) . "\n";
            print("==================== HEX \n");
            print make_hex($record->{'data_blob'}) . "\n";

#             ($a, $b, $c) = unpack('NN', $record->{'data_blob'});
#             print inet_ntoa($a) . "\n";
#             print inet_ntoa($b) . "\n";
#             print inet_ntoa($c) . "\n";
              $a = substr($record->{'data_blob'},1,4);
              $b = substr($record->{'data_blob'},4,4);
              $c = substr($record->{'data_blob'},8,4);
             print sprintf("%d",unpack('N',$a)) . "\n";
             print sprintf("%d",unpack('N',$b)) . "\n";
             print inet_ntoa($c) . "\n";
        }
    }
    print("\n");
  }

  print("Exited while. Deadreads is $UF->{'DEADREADS'}.\n") if $debug;
  
  return 0;
}

sub make_hex() {
    my $data = shift;
    return unpack("h* ",$data);
}

sub make_ascii() {
    my $data = shift;
    my $asc = unpack('a*', $data);
    $asc =~ tr/A-Za-z0-9;:\"\'.,<>[]\\|?\/\`~!\@#$%^&*()_\-+={}/./c;
    return $asc;
}

