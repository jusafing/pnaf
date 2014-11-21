#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use SnortUnified::Handlers(qw(:ALL));
use Data::Dumper;
use Socket;

$file = shift;
$debug = 0;
$UF_Data = {};
$record = {};

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

register_handler("unified2_extra_data",\&handle_xff);

while (1) {
    read_records();
}

closeSnortUnified();
return 0;

sub read_records() {
  while ( $record = readSnortUnifiedRecord() ) {

    print "record type " . $record->{'TYPE'} . " is " . $UNIFIED2_TYPES->{$record->{'TYPE'}} . "\n";
    next unless $record->{'TYPE'} eq $UNIFIED2_EXTRA_DATA;

    print Dumper($record);
    
    # the handler will have populated teh 'xff' field by the time we get here
    foreach $field ( @{$record->{'FIELDS'}} ) {
        if ( $field ne 'pkt' && $field ne 'data_blob' ) {
            print("Field " . $field . " : " . $record->{$field} . "\n");
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

sub handle_xff($) {
    $rec = shift;
    return unless $rec->{'type'} eq 1;
    $xff_blob = $rec->{'data_blob'};
    # We know for these records (assuming IPV4) that they are 4 bytes at the end
    # I'll revisit it when someone sends more samples and I have in-field test cases
    $rec->{'xff'} = inet_ntoa(substr($xff_blob,8,4));
    return $rec->{'xff'};
}



