#!/usr/bin/perl -I..

use SnortUnified(qw(:ALL));
use SnortUnified::MetaData(qw(:ALL));
use SnortUnified::TextOutput(qw(:ALL));
use Sys::Syslog;

$file = shift;
$debug = 0;
$UF_Data = {};
$record = {};
$prepend = "Snort Alert:";

$sids = get_snort_sids("/Users/jbrvenik/src/test/sid-msg.map",
                       "/Users/jbrvenik/src/test/gen-msg.map");
$class = get_snort_classifications("/Users/jbrvenik/src/test/classification.config");

$UF_Data = openSnortUnified($file);
die unless $UF_Data;

if ( $UF_Data->{'TYPE'} eq 'LOG' ) {
    closeSnortUnified();
    die("$0 does not handle unified log files");
}


openlog($prepend, 'cons,pid', 'local1');
syslog('info', "$0: Processing file $file");

while ( $record = readSnortUnifiedRecord() ) {
    
    syslog('alert', format_alert($record, $sids, $class));
    
}

closelog();
closeSnortUnified();

