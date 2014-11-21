#!/usr/bin/perl

readBroLog();
sub readBroLog
{
    my $file = $ARGV[0];
    print "Reading $ARGV[0]\n";
    if ( open (FH_BROLOG, $file) )
    {
	print "Opened $ARGV[0]\n";
	my $fs;
	my @field;
	while ( <FH_BROLOG> )
	{
	    chomp();
	    if ( $_ =~ m/^#separator (.*)/ )
	    {
		$fs = $1;
		print "FIELD SEPARATOR: ($fs)\n";
	    }
	    elsif ( $_ =~ m/^#fields(.*)/ )
	    {
		print "Line: ($1)\n";
		@field = split(/$fs/,$1);
		my $cnt = 0;
		foreach my $f (@field)
		{
		    print "FIELD: $f - $cnt\n";
		    $cnt++;
		}
	    }
	    else
	    {
		next if ( $_ =~ m/^#/ );
#		while ( <FH_BROLOG> )
#		{
#		}
	    }
	}	
    }
    else
    {
	print "ERROR\n";
    }
}
