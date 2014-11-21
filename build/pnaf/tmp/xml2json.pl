use XML::XML2JSON;

my $xml = "";
if ( open(FH,$ARGV[0]) )
{
    while(<FH>)
    {
	$xml .= $_;
    }
    close(FH);
}
my $XML2JSON = XML::XML2JSON->new();
my $JSON = $XML2JSON->convert($xml);
open(NF,">$ARGV[0].json");
print NF $JSON;
close(NF);
