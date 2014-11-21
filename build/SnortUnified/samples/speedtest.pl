#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));

$file = shift;
$debug = 0;
$UF_Data = {};
$record = {};

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

# exit at first EOF condition
$UF_Data->{'TOLERANCE'} = 0;

$i = 1;

read_records();

print $i . "\n";

closeSnortUnified();
exit 0;

sub read_records() {
  while ( $record = readSnortUnifiedRecord() ) {
    $i++;
   }
  return 0;
}

