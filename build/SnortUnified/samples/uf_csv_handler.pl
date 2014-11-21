#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use SnortUnified::Handlers(qw(:ALL));

$file = shift;
$debug = 0;
$UF_Data = {};
$record = {};

# Handlers come before qualifiers come before pcre

# handlers will be run and regardless of the result processing will continue
# The available handlers for SnortUnified.pm are
# ("unified_opened", $UF);
# ("unified2_event", $UF_Record);
# ("unified2_packet", $UF_Record);
# ("unified2_unhandled", $UF_Record);
# ("unified2_record", $UF_Record); 
# ("unified_record", $UF_Record);
# ("unified2_extra_data", $UF_Record)
# ("read_data", ($readsize, $buffer));
# ("read_header", $h);

# register_handler('unified2_packet', \&make_hex_pkt);
register_handler('unified2_packet', \&make_ascii_pkt);
# register_handler('unified_record', \&make_hex_pkt);
register_handler('unified_record', \&make_ascii_pkt);
# register_handler does not care about return values so the following will continue
# register_handler('unified_record', \&make_noise_fail);
# register_handler('unified_record', \&make_noise);

register_handler('unified2_record', \&printrec);
register_handler('unified_record', \&printrec);

# show_handlers();

# Qualifiers will be run, if any return a value < 1 
# then the record will be discarded and processing will continue
# with the next record in the file
# Only one option for unified types

# Skip all but sid 402
# register_qualifier(0,0,0, sub{return 0;});
# By having something specific for 402
# register_qualifier(0,1,402, \&printrec);
# register_qualifier(0,1,402, sub{return 1;});
# register_qualifier(0,1,402, \&make_noise);
# register_qualifier(0,1,402, \&make_noise);
# register_qualifier(0,1,402, \&make_noise_fail);
# register_qualifier(0,1,402, \&make_noise_never);

# But you can be granular with unified2 types
# register_qualifier($UNIFIED2_IDS_EVENT,1,402, \&make_noise);
# register_qualifier($UNIFIED2_PACKET,1,402, \&make_noise);


# register_pcre(1,402, "test");
# register_pcre(1,402, "*");
# register_pcre(1,402, ".*ads.clickagents.com.*");

# show_qualifiers();

$UF_Data = openSnortUnified($file);\
die unless $UF_Data;
$UF_Data->{'TOLERANCE'} = 0;

while (read_records()){};

closeSnortUnified();
exit 0;

#############################################

sub read_records() {
  # while ( $record = readSnortUnifiedRecord() ) {printrec($record);}
  # XXX - Note how there is no body in this code to print anything
  while ( $record = readSnortUnifiedRecord() ) {}

  print("Exited while. Deadreads is $UF->{'DEADREADS'}.\n") if $debug;
  
  return 0;
}

sub printrec() {
  $rec = shift;

  # print $UNIFIED2_TYPES->{$rec->{'TYPE'}};
  foreach $field ( @{$rec->{'FIELDS'}} ) {
    # if ( $field ne 'pkt' ) {
      print($rec->{$field} . ",");
    # }
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

