#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));

$file = shift;
$debug = 0;
$UF_Data = {};
$record = {};

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

print("row");
foreach $field ( @{$record->{'FIELDS'}} ) {
    if ( $field ne 'pkt' ) { 
        print("," . $field);
    }
}
print("\n");

$i = 1;

while (1) {
    read_records();
}

closeSnortUnified();
return 0;

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

  print("Exited while. Deadreads is $UF->{'DEADREADS'}.\n") if $debug;
  
  return 0;
}

