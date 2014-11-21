#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use SnortUnified::Handlers(qw(:ALL));

$file = shift;
$debug = 0;
$UF_Data = {};
$record = {};

# Handlers come before qualifiers come before pcre

register_handler('unified2_packet', \&make_ascii_pkt);
register_handler('unified_record', \&make_ascii_pkt);

# Skip all but sid 402
register_qualifier(0,0,0, sub{return 0;});
# By having something specific for 402
register_qualifier(0,1,402, sub{return 1;});

# register_pcre(1,402, "test");
# register_pcre(1,402, "*");
register_pcre(1,402, ".*ads.clickagents.com.*");

$UF_Data = openSnortUnified($file);\
die unless $UF_Data;
$UF_Data->{'TOLERANCE'} = 0;

while (read_records()){};

closeSnortUnified();
exit 0;

#############################################

sub read_records() {
  while ( $record = readSnortUnifiedRecord() ) {printrec($record);}

  print("Exited while. Deadreads is $UF->{'DEADREADS'}.\n") if $debug;
  
  return 0;
}

sub printrec() {
  $rec = shift;

  foreach $field ( @{$rec->{'FIELDS'}} ) {
      print($rec->{$field} . ",");
  }
  print($i++ . "\n");

  return 1;

}

sub make_hex_pkt() {
    my $rec = shift;
    my $pkt = $rec->{'pkt'};
    $rec->{'pkt'} = unpack("h* ",$pkt);
}

sub make_ascii_pkt() {
    my $rec = shift;
    my $asc = unpack('a*', $rec->{'pkt'});
    $asc =~ tr/A-Za-z0-9;:\"\'.,<>[]\\|?\/\`~!\@#$%^&*()_\-+={}/./c;
    $rec->{'pkt'} = $asc;
}

sub make_noise() {
  $rec = shift;

  print("MAKE NOISE");
  print("#" x 20 . "\n");

  return 1;
}

sub make_noise_fail() {
  $rec = shift;

  print("MAKE NOISE FAIL");
  print("#" x 40 . "\n");

  return 0;
}

sub make_noise_never() {
  $rec = shift;

  print("MAKE NOISE NEVER");
  print("#" x 60 . "\n");

  return 1;
}

