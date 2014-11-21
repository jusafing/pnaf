#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use Digest::MD5 qw(md5 md5_base64);
use MIME::Base64; 
use Devel::Hexdump 'xd';

$file = shift || die("Usage: $0 <unified file>\n");
$debug = 0;
$UF_Data = {};
$record = {};
$logdata = undef;
$signature = undef;

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

print("file,record");
foreach $field ( @{$record->{'FIELDS'}} ) {
    if ( $field ne 'pkt' ) { 
        print("," . $field);
    } else {
        print(",pktmd5,");
    }
}
print("recmd5\n");

$i = 1;
while ( $record = readSnortUnifiedRecord() ) {
    
    print($file . "," . $i++);;
    
    foreach $field ( @{$record->{'FIELDS'}} ) {
        if ( $field ne 'pkt' ) {
            print("," . $record->{$field});
        } else {
            print md5_base64($record->{$field}) . ",";
        }
    }
#    print md5_base64($record->{'raw_record'});
#    print encode_base64($record->{'raw_record'});
#    print encode_base64($record->{'raw_record'});

#print xd $record->{'raw_record'}, {
#    row   => 10, # print 10 bytes in a row
#    cols  => 2,  # split in 2 column groups, separated with <hsp?>
#      hsp => 2,  # add 2 spaces between hex columns
#      csp => 1,  # add 1 space between char columns
#    hpad  => 1,  # pad each hex byte with 1 space (ex: " 00" )
#    cpad  => 1,  # pad each char byte with 1 space
#};

# or just
print "\n";
print xd $record->{'raw_record'};
    print("\n");

}

closeSnortUnified();

