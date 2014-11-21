#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use SnortUnified::MetaData(qw(:ALL));
use XML::Writer;
use Socket;

$file = shift;
$debug = 0;
$UF_Data = {};
$record = {};
$prepend = "Snort Alert:";

$sids = get_snort_sids("/Users/jbrvenik/src/test/unified/sid-msg.map",
                       "/Users/jbrvenik/src/test/unified/gen-msg.map");
$class = get_snort_classifications("/Users/jbrvenik/src/test/unified/classification.config");

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

my $xml = new XML::Writer();

$xml->xmlDecl();
$xml->comment("Generated from a unified " . $UF_Data->{'TYPE'} . " file " . $file);
$xml->startTag("SnortData");
print("\n");
while ( $record = readSnortUnifiedRecord() ) {
    
    print("\t");
    $xml->startTag('Event');
    $xml->characters($record->{'event_id'});
    print("\n");

    foreach $field ( @{$record->{'FIELDS'}} ) {
      if ($field ne 'pkt') {
        print("\t\t");
        $xml->startTag($field);
        $xml->characters($record->{$field});
        $xml->endTag($field);
        print("\n");
        if ( $field eq 'tv_sec' || $field eq 'tv_sec2' ) {
            print("\t\t");
            $xml->startTag($field . "_h");
            $xml->characters(scalar gmtime($record->{$field}));
            $xml->endTag($field . "_h");
            print("\n");
        }
        if ( $field eq 'sip' || $field eq 'dip' ) {
            print("\t\t");
            $xml->startTag($field . "_h");
            $xml->characters(inet_ntoa(pack('N', $record->{$field})));
            $xml->endTag($field . "_h");
            print("\n");
        }
      } else {
        print("\t\t");
        $xml->startTag($field);
        print("\n");
        print_pkt("\t\t\t", $record->{$field});
        print("\t\t");
        $xml->endTag($field);
        print("\n");
      }
    }
    print("\t");
    $xml->endTag('Event');
    print("\n");
    
}
$xml->endTag("SnortData");

$xml->end();
closeSnortUnified();


sub print_pkt($$) {
    my $indent = $_[0];
    my $data = $_[1];
    my $buff = '';
    my $hex = '';
    my $ascii = '';
    my $count = 0;
    my $ret = "";

    for (my $i = 0;$i < length($data);$i += 16) {
       $buff = substr($data,$i,16);
       $hex = join(' ',unpack('H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2',$buff));
       $ascii = unpack('a16', $buff);
       $ascii =~ tr/A-Za-z0-9;:\"\'.,<>[]\\|?\/\`~!\@#$%^&*()_\-+={}/./c;
       $xml->characters(sprintf("$indent%.4X: %-50s%s\n", $count, $hex, $ascii));
       $count += length($buff);
    }
  return $ret;
}

