#!/usr/bin/perl -I.. 
use strict;
use warnings;
use SnortUnified(qw(:ALL));
use SnortUnified::MetaData(qw(:ALL));
use SnortUnified::TextOutput(qw(:ALL));
use Digest::MD5 qw(md5 md5_base64);
use MIME::Base64; 
use Devel::Hexdump 'xd';

local $SIG{__WARN__} = sub {                                                    
    my $message = shift;                                                        
    print "WWWWWW: $message \n";             
};

my $file = shift || die("Usage: $0 <unified file>\n");

my $sids = get_snort_sids ("/pnaf/modules/dpm/idse/snort2.9.6.1/etc/sid-msg.map",
			   "/pnaf/modules/dpm/idse/snort2.9.6.1/etc/gen-msg.map");
my $class = get_snort_classifications("/pnaf/modules/dpm/idse/snort2.9.6.1/etc/classification.config");

my $UF_Data = openSnortUnified($file);
die unless $UF_Data;

#$i = 1;
while ( my $record = readSnortUnified2Record() )
{
    print "################################################3\n";
    if ( $sids, $record->{'generator_id'} && $record->{'signature_id'} &&
	 $record->{'signature_revision'} )
    {
	print "GENID $record->{'generator_id'}\n";
	print "SIGID $record->{'signature_id'}\n";
	print "REVID $record->{'signature_revision'}\n";
	my $msg = get_msg($sids, $record->{'generator_id'},
                  $record->{'signature_id'}, $record->{'signature_revision'});
	my $cla = get_class($class, $record->{'classification_id'});
	print "MSG ALERT: $msg\n";
	print "CLASS: $cla\n";
    }
    foreach my $key (keys%$record)
    {
        unless ( $key =~ m/^(raw_record|pkt)$/ )
	{
	    if ( $key eq 'FIELDS' )
	    {
#		foreach $f (@{$record->{$key}})
#		{
#		    print "  -Keyfield: $f\n";
#		}
	    }
	    else
	    {
		
		print "Key: $key:\t ($record->{$key})\n";
	    }
        }
	else
	{
            print "Key: $key: B64 :\t" . md5_base64($record->{$key}) . "\n";
	    #print "Key: $key: HEX :\t\n". xd $record->{$key};
	    print xd $record->{$key}, {
		row   => 16, # print 10 bytes in a row
		cols  => 2,  # split in 2 column groups, separated with <hsp?>
		hsp   => 0,  # add 2 spaces between hex columns
		csp   => 0,  # add 1 space between char columns
		hpad  => 1,  # pad each hex byte with 1 space (ex: " 00" )
		cpad  => 0,  # pad each char byte with 1 space
	    };
        }

    }
}

closeSnortUnified();


