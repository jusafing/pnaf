#!/usr/bin/perl
use strict;
use JSON::XS;

my @files = split(",",$ARGV[0]);
my %nvdpnaf;
my %stats;

foreach my $file ( @files )
{
    print "Parsing JSON file ($file)\n";
    my $content = "";
    open(FH,$file);
    while(<FH>)
    {
	$content .= $_;
    }
    close(FH);
    my $nvdhash = decode_json ($content); # More efficient    

    foreach my $entry (keys$nvdhash->{nvd}{entry})
    {
	if ( ref($nvdhash->{nvd}{entry}[$entry]{
	     'vuln$vulnerable-software-list'}{'vuln$product'}) eq "HASH" )
	{
	    foreach my $prod (keys%{$nvdhash->{nvd}{entry}[$entry]{
			'vuln$vulnerable-software-list'}{'vuln$product'}})
	    {
		if ( ref($prod) )
		{
		    my @fld = split(":",$prod->{'$t'});
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Description'} = $nvdhash->{nvd}{entry}[$entry]{
			'vuln$summary'}{'$t'};
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Score'} = $nvdhash->{nvd}{entry}[$entry]{
			'vuln$cvss'}{'cvss$base_metrics'}{'cvss$score'}{'$t'};
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Vulnerable Software'}{$fld[2]}{$fld[3]}{$fld[4]}++;
		    $stats{Products}{$fld[3]}++;
		    $stats{Versions}{"$fld[3]$fld[4]"}++;
		}
		else
		{
		    my @fld = split(":",$nvdhash->{nvd}{entry}[$entry]{
			'vuln$vulnerable-software-list'}{'vuln$product'}{
			$prod});
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Description'} = $nvdhash->{nvd}{entry}[$entry]{
			'vuln$summary'}{'$t'};
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Score'} = $nvdhash->{nvd}{entry}[$entry]{
			'vuln$cvss'}{'cvss$base_metrics'}{'cvss$score'}{'$t'};
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Vulnerable Software'}{$fld[2]}{$fld[3]}{$fld[4]}++;
		    $stats{Products}{$fld[3]}++;
		    $stats{Versions}{"$fld[3]$fld[4]"}++;
		}
	    }
	}
	elsif ( ref($nvdhash->{nvd}{entry}[$entry]{
	     'vuln$vulnerable-software-list'}{'vuln$product'}) eq "ARRAY" )
	{
	    foreach my $prod (@{$nvdhash->{nvd}{entry}[$entry]{
			'vuln$vulnerable-software-list'}{'vuln$product'}})
	    {
		if ( ref($prod) )
		{
		    my @fld = split(":",$prod->{'$t'});
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Description'} = $nvdhash->{nvd}{entry}[$entry]{
			'vuln$summary'}{'$t'};
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Score'} = $nvdhash->{nvd}{entry}[$entry]{
			'vuln$cvss'}{'cvss$base_metrics'}{'cvss$score'}{'$t'};
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Vulnerable Software'}{$fld[2]}{$fld[3]}{$fld[4]}++;
		    $stats{Products}{$fld[3]}++;
		    $stats{Versions}{"$fld[3]$fld[4]"}++;
		}
		else
		{
		    my @fld = split(":",$nvdhash->{nvd}{entry}[$entry]{
			'vuln$vulnerable-software-list'}{'vuln$product'}{
			$prod});
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Description'} = $nvdhash->{nvd}{entry}[$entry]{
			'vuln$summary'}{'$t'};
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Score'} = $nvdhash->{nvd}{entry}[$entry]{
			'vuln$cvss'}{'cvss$base_metrics'}{'cvss$score'}{'$t'};
		    $nvdpnaf{CVEs}{$nvdhash->{nvd}{entry}[$entry]{'@id'}}{
			'Vulnerable Software'}{$fld[2]}{$fld[3]}{$fld[4]}++;
		    $stats{Products}{$fld[3]}++;
		    $stats{Versions}{"$fld[3]$fld[4]"}++;
		}
	    }
	}
	else
	{
	}
    }
}


$nvdpnaf{Summary}{'CVEs Counter'} = keys$nvdpnaf{CVEs};
$nvdpnaf{Summary}{'Products Counter'} = keys$stats{Products};
$nvdpnaf{Summary}{'Versions Counter'} = keys$stats{Versions};
my $json_text = encode_json \%nvdpnaf;
open(FO,">nvd.json");
print FO $json_text;
close(FO);
print "Stats\n";
print "Parsed ($nvdpnaf{Summary}{'CVEs Counter'}) CVE entries\n";
print "Parsed ($nvdpnaf{Summary}{'Products Counter'}) Products\n";
print "Parsed ($nvdpnaf{Summary}{'Versions Counter'}) Versions\n";

