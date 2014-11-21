#!/usr/bin/perl -w
#############################################################################
# PASSIVE NETWORK AUDIT FRAMEWORK                                           
# Version 0.1.0                                                            
# By Javier Santillan [2014]                                               
# --------------------------------------------------------------------------
#                                                                            
# File          : PNAF DPM module                                        
# Description   : Standard variables and function for Data Processing Module
#                                                                            
##############################################################################

use strict;
use warnings;
use Pnaf::Core;
use IO::CaptureOutput qw/capture_exec/;
use URI::Encode qw(uri_encode uri_decode);
use HTTP::BrowserDetect;
use String::Tokenizer;
use Time::Piece;
use JSON::XS;
use JSON::Parse 'parse_json';
use SnortUnified(qw(:ALL));
use SnortUnified::MetaData(qw(:ALL));
use SnortUnified::TextOutput(qw(:ALL));
use Digest::MD5 qw(md5 md5_base64);
use Devel::Hexdump 'xd';
use Net::Subnet;
use POSIX;

#package GV;
my %processTool = (
    argusFlow  	=> \&processArgusFlow,
    p0f   	=> \&processP0f,
    prads 	=> \&processPrads,
    snortAppId  => \&processSnortAppId,
    suricataHttp=> \&processSuricataHttp,
    suricataEve => \&processSuricataEve,
    snortIds 	=> \&processSnortIds,
    httpry	=> \&processHttpry,
    tcpdstat 	=> \&processTcpdstat,
    tcpflow 	=> \&processTcpflow,
    bro 	=> \&processBro,
    );
my %auditS  ;
my %auditT  ;
my %auditSW ;
my %auditOUT;
##############################################################################
## Description: Executes PNAf instance in offline mode
## Syntax     : loadPnafInstance(CURRENT_FUNCTION, CAPFILE, OUTDIR)
##############################################################################
sub loadPnafInstance
{
    my ($caller, $capfile, $outdir) = @_;
    my $self = getFunctionName($caller,(caller(0))[3]);
    my $instance_logdir = $outdir;
    my $instance_name;

    unless ( $CFG::args{log_dir} )
    {
	logMsgT($self, "Creating output directories",
		2, $CFG::options{log_file});
	my $timeid = time;
	$instance_name   = "instance\_$timeid";
	$instance_logdir = "$outdir/$instance_name";
    }
    execute($self, "mkdir", $instance_logdir);
    execute($self, "mkdir", "$instance_logdir/chaosreader");
    execute($self, "mkdir", "$instance_logdir/tcpxtract");
    execute($self, "mkdir", "$instance_logdir/bro");

    logMsgT($self, "Loading PNAF instance for ($capfile)",
	    2, $CFG::options{log_file});
    loadEngine($self,"npee", $capfile,$instance_logdir);
    loadEngine($self,"idse", $capfile,$instance_logdir);
    loadEngine($self,"nfae", $capfile,$instance_logdir);
    loadEngine($self,"dpie", $capfile,$instance_logdir);
    logMsgT($self, "Raw data logs stored in ($instance_logdir)",
	    2, $CFG::options{log_file});
    return $instance_name;
}
##############################################################################
## Description: Executes an specified engine
## Syntax     : loadEngine(CURRENT_FUNCTION, ENGINE, CAPFILE, OUTDIR)
##############################################################################
sub loadEngine
{
    my ($caller, $engine, $capfile, $outdir) = @_;
    my $self  	= getFunctionName($caller,(caller(0))[3]);
    my @tools		;
    my $status		;
    my $engine_name	;
    if    ( $engine eq "npee" )
    {
	@tools 		= ('p0f', 'prads');
	$engine_name 	= "Network Profiling and enumeration Engine <NPEE>";
    }
    elsif ( $engine eq "idse" )
    {
	@tools 		= ('snort', 'suricata', 'bro');
	$engine_name 	= "Intrusion Detection System Engine <IDSE>";
    }
    elsif ( $engine eq "nfae" )
    {
#	@tools 		= ('cxtracker', 'argus', 'ra', 'tcpdstat', 'tcpflow');
	@tools 		= ('argus', 'ra', 'tcpdstat');
	$engine_name 	= "Network Flow Analysis Engine <NFAE>";
    }
    elsif ( $engine eq "dpie" )
    {
	@tools 		= ('httpry');
#	@tools 		= ('chaosreader', 'nftracker', 'httpry', 'passivedns');
#			   'ssldump', 'dnsdump', 'passivedns', 'tcpxtract');
	$engine_name 	= "Deep Packet Inspection Engine <DPIE>";
    }
    elsif ( $engine eq "nsae" )
    {
	$engine_name 	= "Network Security Audit Engine <NSAE>";
    }

    logMsgT($self,"Executing $engine_name",2,$CFG::options{log_file});
    foreach my $tool ( @tools )
    {
	$status = execute($self, $tool, $capfile, $outdir);
    }
}

##############################################################################
## Description: Runs a specified tool passed as argument with PNAF options.
##		It receives STDERR, STDOUT and EXIT_STATUS to put them into
##		the PNAF fixed log format
## Syntax     : execute(CURRENT_FUNCTION, TOOL_NAME, INFILE, OUTDIR)
##############################################################################
sub execute
{
    my ($caller, $tool, $infile, $outdir) = @_;
    my $self  	= getFunctionName($caller,(caller(0))[3]);
    my $exec_line;
    my $old_dir;
    my $bro_dir;

    if ( $tool =~ m/^(mkdir|cp|mv)$/ )
    {
	logMsgT($self," |-- $1 -> ($infile)", 3, $CFG::options{log_file});
    }
    elsif ( $tool =~ m/^bro$/ )
    {
	# Since there is no command line option to specify output directory in
	# BRO, then chdir is used.
	#
	$old_dir = getcwd();
	logMsgT($self," |--Changing working directory for BRO ($outdir/bro)",
		3, $CFG::options{log_file});
	chdir "$outdir/bro";
	logMsgT($self," |--Running $tool version $CFG::versions{$tool}",
		2, $CFG::options{log_file});
    }
    elsif ( $tool =~ m/^(chaosreader|nftracker|httpry|passivedns)$/ ||
	    $tool =~ m/^(cxtracker|argus|ra|tcpdstat|tcpflow)$/ ||
	    $tool =~ m/^(snort|suricata|p0f|prads)$/ )
    {
	logMsgT($self," |--Running $tool version $CFG::versions{$tool}",
		2, $CFG::options{log_file});
    }
    else
    {
	logMsgT($self,"Invalid tool ($tool)", 0, $CFG::options{log_file});
    }

    # To show the command and its arguments
    my @cmd = getToolCmd($self, $tool, $infile, $outdir);
    foreach my $arg (@cmd)
    {
	$exec_line .= "$arg ";
    }
    logMsgT($self, "Exec line of ($tool) => ($exec_line)",
	    3, $CFG::options{log_file});
    my ($stdout, $stderr, $success, $exit_status) = capture_exec( @cmd );
    my @stdout_lines = split(/\n/, $stdout);
    my @stderr_lines = split(/\n/, $stderr);
        
    # To show the tool's output sent to STDOUT (only DEBUG mode)
    foreach my $line (@stdout_lines)
    {
	logMsgT($self,"<".uc($tool)."> $line", 3, $CFG::options{log_file}); 
    }
    # To show the tool's output sent to STDERR
    foreach my $line (@stderr_lines)
    {
	logMsgT($self,
		"<".uc($tool)."> $line", 3, $CFG::options{log_file}); 
    }

    # To show execution status
    if ( $exit_status != 0 )
    {
        logMsgT($self,
	    " |--Failed to execute (tool): ($exec_line). Exit status: ($!).".
	    " Check output log ($outdir/$tool.execlog*)",
	    0, $CFG::options{log_file});
	saveContent($self,$stdout ,"$outdir/$tool.execlog.std") if ($stdout);
	saveContent($self,$stderr ,"$outdir/$tool.execlog.err") if ($stderr);
	saveContent($self,$success,"$outdir/$tool.execlog.suc") if ($success);
    }
    else
    {
	unless ( $tool =~ m/^(mkdir|cp|mv)$/ )
	{
	    logMsgT($self,
		" |--($tool) has finished successfully. Status ($exit_status)",
		2, $CFG::options{log_file});
	}
	# If the tool only outputs to STDOUT, the a saveContent function will
	# be used in order to log the output into a log file
	if    ( $tool eq "tcpdstat" )
	{
	    saveContent($self, $stdout,
		       "$outdir/tcpdstat.log");
	}
	if    ( $tool eq "ra" )
	{
	    saveContent($self, $stdout,
		       "$outdir/argusFlow.log");
	}
	elsif ( $tool eq "bro" )
	{
	    chdir $old_dir;
	}
	elsif ( $tool eq "snort" )
	{
	    if ( opendir(DIR, $outdir) )
	    {
		my $infile ;
		while (my $file = readdir(DIR))
		{
		    next if ($file =~ m/^\./);
		    if ($file =~ m/appstats-unified.log/ )
		    {
			$infile = "$outdir/$file";
		    }
		}
		closedir(DIR);
		my @cmd = getToolCmd($self, "snortAppId", $infile, $outdir);
		my ($stdout,$stderr,$success,$exit_status)=capture_exec(@cmd);
		my @stdout_lines = split(/\n/, $stdout);
		my @stderr_lines = split(/\n/, $stderr);
		saveContent($self, $stdout,
			   "$outdir/snortAppId.log");
	    }
	    else
	    {
		logMsgT($self,
			"Unable to read log directory $outdir",
			0, $CFG::options{log_file});
	    }
	}
    }
    return $exit_status;
}

##############################################################################
## Description: Returns the execution arguments for a requested tool.
## Syntax     : getToolCmd(CURRENT_FUNCTION, TOOL_NAME, INPUTFILE)
##############################################################################
sub getToolCmd
{
    my ($caller, $tool, $infile, $outdir) = @_;
    my $self  	= getFunctionName($caller,(caller(0))[3]);
    my @cmd;
    if	  ( $tool eq "p0f" )
    {
	@cmd = ($CFG::files{p0f});
	push @cmd, '-f';
	push @cmd, "$CFG::files{p0f_fp}";
	push @cmd, '-r';
	push @cmd, $infile;
	push @cmd, '-o';
	push @cmd, "$outdir/p0f.log";
    }
    elsif ( $tool eq "prads" )
    {
	@cmd = ($CFG::files{prads});
	push @cmd, '-r';
	push @cmd, $infile;
	push @cmd, '-l';
	push @cmd, "$outdir/prads.log";
	push @cmd, '-c';
	push @cmd, "$CFG::files{prads_conf}";
    }
    elsif ( $tool eq "bro" )
    {
	@cmd = ($CFG::files{bro});
	push @cmd, '-r';
	push @cmd, $infile;
    }
    elsif ( $tool eq "snort" )
    {
	@cmd = ($CFG::files{snort});
	push @cmd, '-U';
	push @cmd, '-r';
	push @cmd, $infile;
	push @cmd, '-l';
	push @cmd, "$outdir";
	push @cmd, '-c';
	push @cmd, "$CFG::files{snort_conf}";
    }
    elsif ( $tool eq "snortAppId" )
    {
	@cmd = ($CFG::files{snortAppId});
	push @cmd, $infile;
    }
    elsif ( $tool eq "suricata" )
    {
	@cmd = ($CFG::files{suricata});
	push @cmd, '-r';
	push @cmd, $infile;
	push @cmd, '-l';
	push @cmd, "$outdir";
	push @cmd, '-c';
	push @cmd, "$CFG::files{suricata_conf}";
    }
    elsif ( $tool eq "cxtracker" )
    {
	@cmd = ($CFG::files{cxtracker});
	push @cmd, '-r';
	push @cmd, $infile;
	push @cmd, '-d';
	push @cmd, "$outdir";
    }
    elsif ( $tool eq "argus" )
    {
	@cmd = ($CFG::files{argus});
	push @cmd, '-r';
	push @cmd, $infile;
	push @cmd, '-w';
	push @cmd, "$outdir/capture.argus";
	push @cmd, '-s';
	push @cmd, '1500';
	push @cmd, '-U';
	push @cmd, '1500';
    }
    elsif ( $tool eq "ra" )
    {
	@cmd = ($CFG::files{ra});
	push @cmd, '-n';
	push @cmd, '-r';
	push @cmd, "$outdir/capture.argus";
	push @cmd, '-u';
	push @cmd, '-c';
	push @cmd, ',';
	push @cmd, '-s';
	push @cmd, 'proto saddr sport daddr dport dir pkts bytes state stime';
	push @cmd, '-';
    }
    elsif ( $tool eq "tcpdstat" )
    {
	@cmd = ($CFG::files{tcpdstat});
	push @cmd, $infile;
    }
    elsif ( $tool eq "chaosreader" )
    {
	@cmd = ($CFG::files{chaosreader});
	push @cmd, '-v';
	push @cmd, '-D';
	push @cmd, "$outdir/chaosreader";
	push @cmd, $infile;
    }
    elsif ( $tool eq "nftracker" )
    {
	@cmd = ($CFG::files{nftracker});
	push @cmd, '-r';
	push @cmd, $infile;
	push @cmd, '-l';
	push @cmd, "$outdir/nftracker.log";
    }
    elsif ( $tool eq "httpry" )
    {
	@cmd = ($CFG::files{httpry});
	push @cmd, '-r';
	push @cmd, $infile;
	push @cmd, '-o';
	push @cmd, "$outdir/httpry.log";
    }
    elsif ( $tool eq "ssldump" )
    {
	@cmd = ($CFG::files{ssldump});
	push @cmd, '-r';
	push @cmd, $infile;
	push @cmd, '-AdX';
    }
    elsif ( $tool eq "passivedns" )
    {
	@cmd = ($CFG::files{passivedns});
	push @cmd, '-r';
	push @cmd, $infile;
	push @cmd, '-l';
	push @cmd, "$outdir/passivedns.log";
    }
    elsif ( $tool eq "tcpxtract" )
    {
	@cmd = ($CFG::files{tcpxtract});
	push @cmd, '-f';
	push @cmd, $infile;
	push @cmd, '-c';
	push @cmd, "$CFG::options{path}/etc/tcpxtract.conf";
	push @cmd, '-o';
	push @cmd, "$outdir/tcpxtract/";
    }
    elsif ( $tool eq "tcpflow" )
    {
	@cmd = ($CFG::files{tcpflow});
	push @cmd, '-r';
	push @cmd, $infile;
	push @cmd, '-a';
	push @cmd, '-o';
	push @cmd, "$outdir/tcpflow/";
    }
    elsif ( $tool eq "mkdir" )
    {
	@cmd = ("mkdir");
	push @cmd, '-p';
	push @cmd, "$infile";
    }
    elsif ( $tool eq "mv" )
    {
	@cmd = ("mv");
	my @files = split(/\|/,$infile);
	push @cmd, "$files[0]";
	push @cmd, "$files[1]";
    }
    elsif ( $tool eq "cp" )
    {
	@cmd = ("cp");
	my @files = split(/\|/,$infile);
	push @cmd, '-r';
	push @cmd, "$files[0]";
	push @cmd, "$files[1]";
    }
    else
    {
	logMsgT($self,"The tool ($tool) is not defined on PNAF",
		0, $CFG::options{log_file});
	@cmd = ('pnaf_invalid_tool');
    }
    return @cmd;
}
##############################################################################
## Description: Retrieves enumeration information from p0f and prads.
## Syntax     : getEnumeration(CURRENT_FUNCTION, TOOL_NAME, DATAFILE)
##############################################################################
sub getEnumeration
{
    my ($caller, $tool, $datafile) = @_;
    my $self  	= getFunctionName($caller,(caller(0))[3]);
    if    ( $tool eq "p0f" )
    {
	logMsgT($self,"Processing ($tool) data", 0, $CFG::options{log_file});
    }
    elsif ( $tool eq "prads" )
    {
	logMsgT($self,"Processing ($tool) data", 0, $CFG::options{log_file});
    }
    else
    {
	logMsgT($self,"The tool ($tool) is not defined on PNAF",
		0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Parses P0f data.
## Syntax     : processP0f(CURRENT_FUNCTION, DATAFILE, MODE, QUERY, OUTDIR)
## OPTIONS    : QUERY	'hash'    : Returns a hash with parsing info.
##		       	'json'    : Returns a JSON string with parsing info
##############################################################################
sub processP0f
{
    my ($caller, $datafile, $query, $outdir) = @_;
    my $self  	= getFunctionName($caller,(caller(0))[3]);
    my $parser  = "p0f";
    my %p0f	;
    my $rec	;
    unless ( open(FH_P0F,$datafile) )
    {
	logMsgT($self,"$parser: Unable to open data file ($datafile)",
		0, $CFG::options{log_file});
	return;
    }

    logMsgT($self,"Processing ($datafile)", 3, $CFG::options{log_file});
    # -------------------  Begin parsing process --------------------#
    while ( <FH_P0F> )
    {
	chomp();
	my $line = $_ ;
	my @field = split (/\|/,$_); 
	$field[1] =~ s/cli=//;
	$field[1] =~ s/\/.*//;
	$field[2] =~ s/srv=//;
	$field[2] =~ s/\/.*//;
	$field[0] =~ m/(.*) mod=(.*)/;
    	my $asset;
	my @homenet  = split(",",$CFG::options{home_net});
	my $in_homenet = subnet_matcher(@homenet);
	my $flowid ;
	if ( $in_homenet->($field[1]) )
	{
	    if ( $in_homenet->($field[2]) )
	    {
		$flowid = "Internal-Internal";
	    }
	    else
	    {
		$flowid = "Internal-External";
	    }
	}
	else
	{
	    if ( $in_homenet->($field[2]) )
	    {
		$flowid = "External-Internal";
	    }
	    else
	    {
		$flowid = "External-External";
	    }
	}
	my $flowdst =  $field[2];
	my $ts	    =  $1;
	my $mode    =  $2;
	$ts	    =~ s/\[//;
	$ts	    =~ s/\]//g;
	my $date    = Time::Piece->strptime($ts,$CFG::options{tf_p0f});
	$ts         = $date->epoch;
	## Identify Asset (client/server)
	if    ( $field[3] =~ m/subj=cli/ )
	{
	    $asset = $field[1];
	    $p0f{Summary}{Clients}{$asset}++;
	    $auditS{S}{Assets}{Clients}{$asset}{$parser}++;
	}
	elsif ( $field[3] =~ m/subj=srv/ )
	{
	    $asset = $field[2];
	    $p0f{Summary}{Servers}{$asset}++;
	    $auditS{S}{Assets}{Servers}{$asset}{$parser}++;
	}
	else
	{
	    logMsgT($self, "$parser: Unknown subject ($field[3])",
		    1, $CFG::options{log_file});
	}
	## Initialize hash
	unless(exists $p0f{'Tracking'}{$asset})
	{
	    $p0f{'Tracking'}{$asset}{'Summary'}= {};
	    $p0f{'Tracking'}{$asset}{'Summary'}{Attributes}= {};
	}

	## Attributes
	$p0f{Tracking}{$asset}{Flows}{$flowid}{$flowdst}{Timestamp}{$ts}++;
	if ( $mode eq "mtu" )
	{
	    $field[4] =~ s/link=//g;	# Link field
	    $field[4] =~ s/ /_/g;	# Link field
	    $field[5] =~ s/raw_mtu=//g;	# Link field
	    $p0f{Summary}{Links}{$field[4]}++;
	    $p0f{Tracking}{$asset}{Summary}{Attributes}{MTU}{$field[5]}     ++;
	    $p0f{Tracking}{$asset}{Flows}{$flowid}{$flowdst}{MTU}{$field[5]}++;
	    $p0f{Tracking}{$asset}{Summary}{Attributes}{Link}{$field[4]}    ++;
	    $p0f{Tracking}{$asset}{Flows}{$flowid}{$flowdst}{Link}{$field[4]}++;
	    $auditS{S}{Network}{Links}{$field[4]}{$parser}++;
	    $auditT{T}{$asset}{Summary}{Attributes}{MTU}{$field[5]}         ++;
	    $auditT{T}{$asset}{Summary}{Attributes}{Link}{$field[4]}        ++;
	    $auditT{T}{$asset}{Tracking}{$ts}{Flows}{$flowid}{$flowdst}{
		'Attributes'}{'MTU'}{$field[5]}  ++;
	    $auditT{T}{$asset}{Tracking}{$ts}{Flows}{$flowid}{$flowdst}{
		'Attributes'}{'Link'}{$field[4]} ++;

	}
	elsif ( $mode =~ m/syn.*/ )
	{
	    $field[4] =~ s/os=//g;	# Link field
	    $field[4] =~ s/ /_/g;	# Link field
	    $field[3] =~ m/.*subj=(.*)/ ;
	    my @refs;
	    push @refs, $p0f{Tracking}{$asset}{Summary}{Attributes};
	    push @refs, $p0f{Tracking}{$asset}{Flows}{$flowid}{$flowdst};
	    push @refs, $p0f{Summary};
	    push @refs, $auditS{S}{Software};
	    push @refs, $auditT{T}{$asset}{Tracking}{$ts}{Flows}{$flowid}{
			$flowdst}{'Attributes'};
	    push @refs, $auditT{T}{$asset}{Summary}{'Attributes'};
	    getPlatforms($self, $field[4], \@refs, $parser);
	    $auditSW{S}{$field[4]}{Assets}{$asset}{$ts}++;
	    getSoftwareInfo($self, $auditSW{S}{$field[4]},$field[4], $parser);
	}
	elsif ( $mode =~ m/(host change|ip sharing).*/ )
	{
	    my $mod = $1;
	    $field[4] =~ s/reason=//g;	# Reason field
	    $field[4] =~ s/ /_/g;	# Link field
	    $field[3] =~ m/.*subj=(.*)/ ;
	    $p0f{Tracking}{$asset}{Summary}{Attributes}{$mod}{$field[4]}++;
	    $p0f{Tracking}{$asset}{Flows}{$flowid}{$flowdst}{$mod}{$field[4]}++;
	    $auditS{S}{Assets}{'IP Sharing'}{$asset}{$parser}++;
	}
	elsif ( $mode =~ m/(ip|http|ssl|uptime).*/ )
	{
	}
	else
	{
	    $field[0] =~ m/(mod=.*)/;
	    logMsgT($self, "$parser: Unknown mod ($field[0])",
		    1, $CFG::options{log_file});
	}
    }
    close(FH_P0F);
    # -------------------  End parsing process ----------------------#
    if    ( $query eq "json" )
    {
	$rec  = "\n{";
	$rec .= "\n\t\"Message\":\"Query  'string' is deprecated. ";
	$rec .= "Use 'hash' instead\",";
	$rec .= "\n\t\"Ex. Step1\":".
		"\"my %hash = processP0f('fname','file','hash')\",";
	$rec .= "\n\t\"Ex. Step2\":".
		"\"writeJsonFile('fname',\\%hash,'outfile')\"";
	$rec .= "\n}";
	return $rec;
    }
    elsif ( $query eq "hash" )
    {
        return %p0f;
    }
    else
    {
	logMsgT($self,"$parser: Invalid query ($query)",
		0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Parses PRADS data.
## Syntax     : processPrads(CURRENT_FUNCTION, DATAFILE, QUERY, OUTDIR)
## OPTIONS    : QUERY	'hash'    : Returns a hash with parsing info.
##		       	'json'    : Returns a JSON string with parsing info
##############################################################################
sub processPrads
{
    my ($caller, $datafile, $query, $outdir) = @_;
    my $self  	= getFunctionName($caller,(caller(0))[3]);
    my $parser = "prads";
    my %prads;
    my $rec ;
    unless ( open(FH_PRADS,$datafile) )
    {
	logMsgT($self,"$parser: Unable to open file ($datafile)",
		0, $CFG::options{log_file});
	return;
    }
    # -------------------  Begin parsing process --------------------#
    my $first_line = <FH_PRADS> ; # Get rid of header 
    while ( <FH_PRADS> )
    {
	chomp();
	$_ =~ m/([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),\[(.*)\],([^,]+),([^,]+)/;
	my $asset    = $1;
	my $vlan     = $2;
	my $port     = $3;
	my $proto    = $4;
	my $service  = $5;
	my $servinfo = $6;
	my $ts 	     = $8;
	if ( $service =~ m/(CLIENT|SERVER)/ )
	{
	    my $type = ucfirst(lc($1))."s";
	    $servinfo =~ s/\@/ at standard port of / ;
	    $prads{Summary}{$type}{'IP Address'}{$asset}++;
	    $auditS{S}{Assets}{$type}{$asset}{$parser}++;	
	    $servinfo =~ s/(\[|\])//g;
	    $servinfo =~ m/([^:]+):\@*(.*)/ ;
	    $prads{Summary}{$type}{Services}{$1}{$2}++;
	    $auditS{S}{Software}{Services}{$1}{$2}{$parser}++; 
	    $auditSW{S}{$2}{Assets}{$asset}{$ts}++;
	    getSoftwareInfo($self,$auditSW{S}{$2}, $2, $parser);
	    my $serv = $1;
	    $servinfo =~ s/\@/ at standard port of / ;
	    $prads{Tracking}{$asset}{Summary}{$type}{$serv}{$servinfo}++; 
	    $prads{Tracking}{$asset}{Sessions}{$type}{$ts}{$serv}{$servinfo}++; 
	}
	elsif ( $service =~ m/(SYN|RST|FIN|SYNACK)/ )
	{
	    my $type  = "Attributes";
	    $servinfo =~ s/(\[|\])//g;
	    $servinfo =~ m/([^:]+:+){6}(.*)/ ;
	    my $serv = $2;
	    my $null = "null";
	    $null =~ m/(null)/;
	    $serv =~ m/.*(link:[^:]+):*.*/;
	    unless ($1 =~ m/null/)
	    {
		$prads{Summary}{Links}{$1}++;
		$auditS{S}{Network}{Links}{$1}{$parser}++;
		$prads{Tracking}{$asset}{Summary}{$type}{Links}{$1}++;
		$prads{Tracking}{$asset}{Sessions}{$type}{$ts}{Links}{$1}++;
	    }
	    $serv =~ s/uptime:[^:]+//;
	    $serv =~ s/link:[^:]+//;
	    $serv =~ s/:://;
	    $serv =~ s/unknown://;
	    $serv =~ s/://;

	    my @refs;
	    push @refs, $prads{Tracking}{$asset}{Summary}{$type};
	    push @refs, $prads{Tracking}{$asset}{Sessions}{$type}{$ts};
	    push @refs, $prads{Summary};
	    push @refs, $auditS{S}{Software};
	    getPlatforms($self, $serv, \@refs, $parser);
	    $auditSW{S}{$serv}{Assets}{$asset}{$ts}++;
	    getSoftwareInfo($self,$auditSW{S}{$serv},$serv, $parser);
	}
	else
	{
	    logMsgT($self, "$parser: Unknown service ($service)",
		    1, $CFG::options{log_file});		    
	}
	$prads{Summary}{Vlan}{$vlan}++;
	$prads{Summary}{Protocol}{$proto}++;
	# Protocol is taken from Argus data
	#$auditS{S}{Protocol}{$proto}++;
    }
    close(FH_PRADS);
    # -------------------  End parsing process ----------------------#
    if    ( $query eq "json" )
    {
	$rec  = "\n{";
	$rec .= "\n\t\"Message\":\"Query  'string' is deprecated. ";
	$rec .= "Use 'hash' instead\",";
	$rec .= "\n\t\"Ex. Step1\":".
		"\"my %hash = processPrads('fname','file','hash')\",";
	$rec .= "\n\t\"Ex. Step2\":".
		"\"writeJsonFile('fname',\\%hash,'outfile')\"";
	$rec .= "\n}";
	return $rec;
    }
    elsif ( $query eq "hash" )
    {
        return %prads;
    }
    else
    {
	logMsgT($self,"$parser: Invalid query ($query)",
		0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Parses SNORTOPENAPPID data.
## Syntax     : processSnortAppId(CURRENT_FUNCTION,DATAFILE,QUERY,OUTDIR)
## OPTIONS    : QUERY	'hash'   : Returns a hash with parsing info.
##		       	'json'   : Returns a JSON string with parsing info
##############################################################################
sub processSnortAppId
{
    my ($caller, $datafile, $query, $outdir) = @_;
    my $self 	= getFunctionName($caller,(caller(0))[3]);
    my $parser = "snortAppId";
    my %soai ; 
    my $rec  ;
    unless ( open(FH_SOAI,$datafile) )
    {
	logMsgT($self,"$parser: Unable to open data file ($datafile)",
		0, $CFG::options{log_file});
	return;
    }
    # -------------------  Begin parsing process --------------------#
    while ( <FH_SOAI> )
    {
	chomp();
	my @line = split(/,/,$_);
	$line[1] =~ m/appName="([^"]+)"/;
	my $app = $1;
	next unless ($app);
	$line[2] =~ m/txBytes="([^"]+)"/;
	$soai{$app}{txBytes} = $1;
	$auditS{S}{Software}{Applications}{$app}{txBytes} = $1;
	$line[3] =~ m/rxBytes="([^"]+)"/;
	$soai{$app}{rxBytes} = $1;
	$auditS{S}{Software}{Applications}{$app}{rxBytes} = $1;
    }
    close(FH_SOAI);
    # -------------------  End parsing process ----------------------#

    if    ( $query eq "json" )
    {
	return $rec;
    }
    elsif ( $query eq "hash" )
    {
        return %soai;
    }
    else
    {
	logMsgT($self,"$parser: Invalid query ($query)",
		0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Parses HTTPRY data.
## Syntax     : processHttpry(CURRENT_FUNCTION, DATAFILE, MODE, QUERY, OUTDIR)
## OPTIONS    : QUERY	'hash'    : Returns a hash with parsing info.
##		       	'string'  : Returns a JSON string with parsing info
##############################################################################
sub processHttpry
{
    my ($caller, $datafile, $query, $outdir) = @_;
    my $self	  = getFunctionName($caller,(caller(0))[3]);
    my $parser	  = "httpry";
    my $lfsparser = "lfs_$parser";
    my %httpry ; 
    my $rec  ; 
    unless ( open(FH_HTTPRY,$datafile) )
    {
	logMsgT($self,"Unable to open data file ($datafile)",
		0, $CFG::options{log_file});
	return;
    }
    # Get rif od headers starting with #.
    # Default httpry output creates two header lines
    my $header_line = <FH_HTTPRY> ;
    $header_line = <FH_HTTPRY> ;
    my %field = getLogFields($self,$parser);
    my @registerClient;
    my @registerServer;
    my @register;
    push @registerClient, "Domains";
    push @registerClient, "Resources";
    push @registerClient, "Methods";
    push @registerClient, "Protocols";
    push @registerServer, "Protocols";
    push @registerServer, "Status Codes";
    push @registerServer, "Response Phrases";
    push @register, "Domains";
    push @register, "Resources";
    push @register, "Methods";
    push @register, "Protocols";
    push @register, "Status Codes";
    push @register, "Response Phrases";
    # -------------------  Begin parsing process --------------------#
    while ( <FH_HTTPRY> )
    {
	chomp();
	my @line = split(/$CFG::options{$lfsparser}/,$_);
	my $url  ;
	my $flow ;

	if ($line[$field{'Source IPs'}] &&  $line[$field{'Destination IPs'}] &&
	    $line[$field{'Flow Direction'}] )
	{
	    foreach my $data (@register)
	    {
		if ( $line[$field{$data}] )
		{
		    $httpry{Summary}{$data}{$line[$field{$data}]}++ ;
		    if ( $data eq "Domains" )
		    {
			$auditS{S}{Domains}{$line[$field{$data}]}{
			    $line[$field{'Source IPs'}]}{$parser}++;
		    }
		    else
		    {
			$auditS{S}{Events}{'Events Info'}{Http}{$data}{
			    $line[$field{$data}]}{$parser}++;
		    }
		}
		else
		{
		    logMsgT($self,
			"$parser: Data not found in log field $data ".
			" field ($field{$data}). Possible wrong".
			" format", 1, $CFG::options{log_file});	    
		}
	    }
	    $flow = "$line[$field{'Source IPs'}]:"  	.
		    "$line[$field{'Flow Direction'}]:"  .
		    "$line[$field{'Destination IPs'}]" 	;
	    if    ( $line[$field{'Flow Direction'}] =~ m/^>$/ )
	    {
		$httpry{Summary}{'Clients'}{$line[$field{'Source IPs'}]}++;
		$auditS{S}{Events}{'Events Info'}{Http}{'Clients'}{
		    $line[$field{'Source IPs'}]}{$parser}++ ;
		$httpry{Tracking}{$line[$field{'Source IPs'}]}{Type}{
		    'Clients'}++;
		foreach my $data (@registerClient)
		{
		    if ( $line[$field{$data}] )
		    {
			$httpry{Tracking}{$line[$field{'Source IPs'}]}{
			    "Sessions"}{'Clients'}{$flow}{$data}{
			    $line[$field{$data}]}++;
			$httpry{Tracking}{$line[$field{'Source IPs'}]}{
			    "Summary"}{$data}{$line[$field{$data}]}++;
		    }
		    else
		    {
			logMsgT($self,
			    "$parser: Data not found in logfield $data".
			    " field ($field{$data}). Possible wrong".
			    " format", 1, $CFG::options{log_file});
		    }
		}
		if ($line[$field{Domains}] && $line[$field{Resources}])
		{
		    $url = "http://$line[$field{Domains}]".
			    "$line[$field{Resources}]";
		    $url =~ s/ //g;
		    logMsgT($self,"Parsing tokens from ($url)",
			    3,$CFG::options{log_file});
		    tokenize($self,$url,$httpry{Summary},$parser,'Urls');
		    tokenize($self,$url,$httpry{Tracking}{$line[$field{
			'Source IPs'}]}{'Summary'}, $parser,'Urls');
		    tokenize($self,$url,$httpry{Tracking}{$line[$field{
			'Source IPs'}]}{'Sessions'}{'Clients'}{$flow},
			$parser,'Urls');
		    tokenize($self,$url, $auditS{S}{Events}{
			'Events Info'}{Http}, $parser, 'Urls');
		}
		else
		{
		    logMsgT($self,
			"$parser: Data not found in log field " .
			"Domains/Resource: fields ($field{Domains}&".
			"$field{Resources}). Possible wrong format.", 
			1, $CFG::options{log_file});	    
		}
	    }
	    elsif ( $line[$field{'Flow Direction'}] =~ m/^<$/ )
	    {
		$httpry{Summary}{'Servers'}{$line[$field{
		    'Destination IPs'}]}++;
		$auditS{S}{Events}{'Events Info'}{Http}{'Servers'}{
		$line[$field{'Destination IPs'}]}{$parser}++ ;
		$httpry{Tracking}{$line[$field{'Destination IPs'}]}{Type}{
		    'Servers'}++;
		foreach my $data (@registerServer)
		{
		    if ( $line[$field{$data}] )
		    {
			$httpry{Tracking}{$line[$field{'Destination IPs'}]}{
			    "Sessions"}{'Servers'}{$flow}{$data}{
			    $line[$field{$data}]}++;
			$httpry{Tracking}{$line[$field{'Destination IPs'}]}{
			    "Summary"}{$data}{$line[$field{$data}]}++;
		    }
		    else
		    {
			logMsgT($self,
			    "$parser: Data not found in log field ".
			    " $data, field ($field{$data}). Possible ".
			    "wrong format",1,$CFG::options{log_file});
		    }
		}
	    }
	    else
	    {
		logMsgT($self, "$parser: Unknown flow direction".
			       " $line[$field{'Flow Direction'}]",
			       1, $CFG::options{log_file});
	    }
	}
	else
	{
	    logMsgT($self,
		"Incomplete flow information in suricata log field:" .
		" ($field{'Source IPs'}, $field{'Client Ports'},"    .
		" $field{'Servers'}, $field{'Server Ports'}),"    .
		" $field{'Flow Direction'}. Possible wrong format"   ,
		1, $CFG::options{log_file});
	} 
    }
    close(FH_HTTPRY);
    #-------------------  End parsing process ----------------------

    if    ( $query eq "json" )
    {
	$rec  = "\n{";
	$rec .= "\n\t\"Message\":\"Query  'string' is deprecated. ";
	$rec .= "Use 'hash' instead\",";
	$rec .= "\n\t\"Ex. Step1\": \"my %hash = ".
		"processHttpry('fname','file','hash')\",";
	$rec .= "\n\t\"Ex. Step2\":".
		"\"writeJsonFile('fname',\\%hash,'outfile')\"";
	$rec .= "\n}";
	return $rec;
    }
    elsif ( $query eq "hash" )
    {
        return %httpry;
    }
    else
    {
	logMsgT($self,"Invalid query ($query)",	0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Parses Tcpdstat data.
## Syntax     : processTcpdstat(CURRENT_FUNCTION, DATAFILE,QUERY,OUTDIR)
##############################################################################
sub processTcpdstat
{
    my ($caller, $datafile, $query, $outdir) = @_;
    my $self   = getFunctionName($caller,(caller(0))[3]);
    my $parser = "tcpdstat";
    my %tcpd   ; 
    my $rec    ; 
    my $oldp1  ; 
    my $oldp2  ; 
    unless ( open(FH_TCPDSTAT,$datafile) )
    {
	logMsgT($self,"$parser: Unable to open data file ($datafile)",
		0, $CFG::options{log_file});
	return;
    }
    # -------------------  Begin parsing process --------------------
    while ( <FH_TCPDSTAT> )
    {
	chomp();
	unless ( $_ =~ m/.*### Protocol Breakdown ###.*/)
	{
	    if    ( $_ =~ m/DumpFile: (.*)/ )
	    {
		$auditS{S}{'Capture Info'}{'Capture File'} = $1;
	    }
	    elsif    ( $_ =~ m/FileSize: (.*)/ )
	    {
		$auditS{S}{'Capture Info'}{'File Size'} = $1;
	    }
	    elsif ( $_ =~ m/StartTime: (.*)/ )
	    {
		$auditS{S}{'Capture Info'}{'Start time'} = $1;
	    }
	    elsif ( $_ =~ m/EndTime: (.*)/ )
	    {
		$auditS{S}{'Capture Info'}{'End Time'} = $1;
	    }
	    elsif ( $_ =~ m/TotalTime: (.*)/ )
	    {
		$auditS{S}{'Capture Info'}{'Total Time'} = $1;
	    }
	    elsif ( $_ =~ m/# of packets: (.*)/ )
	    {
		$auditS{S}{'Capture Info'}{'Number of Packets'} = $1;
	    }
	    next;
	}
	my $junk = <FH_TCPDSTAT>;
	$junk    = <FH_TCPDSTAT>;
	$junk    = <FH_TCPDSTAT>;
	while ( <FH_TCPDSTAT> )
	{
	    chomp();
	    my $line = $_;
	    $line =~ s/\)//g;
	    $line =~ s/\(//g;
	    $line =~ s/\[//g;
	    $line =~ s/\]//g;
	    $line =~ 
	    m/([^ ]+) *([^ ]+) *([^ ]+) *([^ ]+) *([^ ]+) *([^ ]+) *([^ ]+) */;
	    if ($1 eq "0")
	    {
		$tcpd{Total}{Count}{PacketsCount} 	= $2;
		$tcpd{Total}{Count}{PacketsPercentage} 	= $3;
		$tcpd{Total}{Count}{BytesCount}    	= $4;
		$tcpd{Total}{Count}{BytesPercentage}   	= $5;
		$tcpd{Total}{Count}{'Bytes/Packets'}	= $6;
	    }
	    elsif ($1 eq "1")
	    {
		$oldp1 = $2;
		$tcpd{Total}{Protocol}{$2}{"$2 Count"}{
		    'PacketsCount'} 		= $3;
		$tcpd{Total}{Protocol}{$2}{"$2 Count"}{
		    'PacketsPercentage'} 	= $4;
		$tcpd{Total}{Protocol}{$2}{"$2 Count"}{
		    'BytesCount'}	   	= $5;
		$tcpd{Total}{Protocol}{$2}{"$2 Count"}{
		    'BytesPercentage'}   	= $6;
		$tcpd{Total}{Protocol}{$2}{"$2 Count"}{
		    'Bytes/Packets'}		= $7;
	    }
	    elsif ($1 eq "2")
	    {
		$oldp2 = $2;
		$tcpd{Total}{Protocol}{$oldp1}{$2}{"$2 Count"}{
		    'PacketsCount'} 		= $3;
		$tcpd{Total}{Protocol}{$oldp1}{$2}{"$2 Count"}{
		    'PacketsPercentage'} 	= $4;
		$tcpd{Total}{Protocol}{$oldp1}{$2}{"$2 Count"}{
		    'BytesCount'}	   	= $5;
		$tcpd{Total}{Protocol}{$oldp1}{$2}{"$2 Count"}{
		    'BytesPercentage'}   	= $6;
		$tcpd{Total}{Protocol}{$oldp1}{$2}{"$2 Count"}{
		    'Bytes/Packets'}		= $7;
		$auditS{S}{Network}{Protocols}{'Packets Count'}{$2}{
		    $parser} = $3;
		$auditS{S}{Network}{Protocols}{'Packets %'}{$2}{
		    $parser} = $4;
		$auditS{S}{Network}{Protocols}{'Bandwith(MB)'}{$2}{
		    $parser} = $5 / 1048576;
		$auditS{S}{Network}{Protocols}{'Bandwith %'}{$2}{
		    $parser} = $6;
		$auditS{S}{Network}{Protocols}{'Bytes/Packet'}{$2}{
		    $parser} = $7;
	    }
	    elsif ($1 eq "3")
	    {
		$tcpd{Total}{Protocol}{$oldp1}{$oldp2}{$2}{"$2 Count"}{
		    'PacketsCount'} 		= $3;
		$tcpd{Total}{Protocol}{$oldp1}{$oldp2}{$2}{"$2 Count"}{
		    'PacketsPercentage'} 	= $4;
		$tcpd{Total}{Protocol}{$oldp1}{$oldp2}{$2}{"$2 Count"}{
		    'BytesCount'}	   	= $5;
		$tcpd{Total}{Protocol}{$oldp1}{$oldp2}{$2}{"$2 Count"}{
		    'BytesPercentage'}   	= $6;
		$tcpd{Total}{Protocol}{$oldp1}{$oldp2}{$2}{"$2 Count"}{
		    'Bytes/Packets'}		= $7;
		$auditS{S}{Network}{Protocols}{'Packets Count'}{$2}{
		    $parser}  = $3;
		$auditS{S}{Network}{Protocols}{'Packets %'}{$2}{
		    $parser}  = $4;
		$auditS{S}{Network}{Protocols}{'Bandwith(MB)'}{$2}{
		    $parser}  =  $5 / 1048576;
		$auditS{S}{Network}{Protocols}{'Bandwith %'}{$2}{
		    $parser}  = $6;
		$auditS{S}{Network}{Protocols}{'Bytes/Packet'}{$2}{
		    $parser}  = $7;
	    }
	    else
	    {
		logMsgT($self,"$parser: Unknown depth. " .
			"Proto ($1)",
			1, $CFG::options{log_file});
	    }
	}
    }
    close(FH_TCPDSTAT);
    # -------------------  End parsing process ----------------------

    if    ( $query eq "json" )
    {
	$rec  = "\n{";
	$rec .= "\n\t\"Message\":\"Query  'string' is deprecated. ";
	$rec .= "Use 'hash' instead\",";
	$rec .= "\n\t\"Ex. Step1\": \"my %hash = ".
		"processHttpry('fname','file','hash')\",";
	$rec .= "\n\t\"Ex. Step2\":".
		"\"writeJsonFile('fname',\\%hash,'outfile')\"";
	$rec .= "\n}";
	return $rec;
    }
    elsif ( $query eq "hash" )
    {
        return %tcpd;
    }
    else
    {
	logMsgT($self,"$parser: Invalid query ($query)",
		0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Parses Suricata IDS data.
## Syntax     : processSuricataIDS(CURRENT_FUNCTION,DATAFILE,MODE,QUERY,OUTDIR)
## OPTIONS    : QUERY	'hash'     : Returns a hash with parsing info.
##		       	'string'   : Returns a JSON string with parsing info
##############################################################################
sub processSuricataEve
{
    my ($caller, $datadir, $query, $outdir) = @_;
    my $self   = getFunctionName($caller,(caller(0))[3]);
    my $parser = "suricataEve";
    my %sids ; 
    my $rec  ; 
    my $datafile = "$datadir/$parser.log";
    unless ( -f $datafile )
    {
	logMsgT($self,"$parser: Unable to open data file ($datafile)",
		0, $CFG::options{log_file});
	return;
    }
    my $datahash = getJsonEvents($self,$datafile, "hash");
    # -------------------------  Begin parsing process -----------------------#
    foreach my $evt (keys%$datahash)
    {
	# Basic validation of required fields---------------------------------#
	next unless ( $datahash->{$evt}{event_type} );
	unless ( $datahash->{$evt}{src_ip} && $datahash->{$evt}{src_ip} )
	{
	    logMsgT($self,"$parser: No SRC/DST IP found in event",
		1, $CFG::options{log_file});
	    next;
	}
	# SRC IP--------------------------------------------------------------#
	my $parserevt = "$parser-$datahash->{$evt}{event_type}";
	$sids{Summary}{'Source IP'}{$datahash->{$evt}{src_ip}}++ ;
	$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Summary}{
	    'Event Types'}{$datahash->{$evt}{event_type}}++;
	$auditS{S}{Assets}{Flows}{'Source IP'}{'Flows Count'}{
	    $datahash->{$evt}{src_ip}}{$parserevt}++;
	# SRC Port------------------------------------------------------------#
	if ( $datahash->{$evt}{src_port} )
	{
	    $sids{Summary}{'Source Port'}{$datahash->{$evt}{src_port}}++ ;
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Summary}{
		'Source Port'}{$datahash->{$evt}{src_port}}++;
	    $auditS{S}{Assets}{Flows}{'Source Port'}{'Flows Count'}{
		$datahash->{$evt}{src_port}}{$parserevt}++;
	}
	# DST IP--------------------------------------------------------------#
	$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Summary}{'Dest IP'}{
	    $datahash->{$evt}{dest_ip}}++;
	# DST Port------------------------------------------------------------#
	if ( $datahash->{$evt}{dest_port} )
	{
	    $sids{Summary}{'Dest Port'}{$datahash->{$evt}{dest_port}}++ ;
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Summary}{
		'Dest Port'}{$datahash->{$evt}{dest_port}}++;
	    $auditS{S}{Assets}{Flows}{'Dest Port'}{'Flows Count'}{
		$datahash->{$evt}{dest_port}}{$parserevt}++;
	}	
	# DST IP--------------------------------------------------------------#
	$sids{Summary}{'Dest IP'}{$datahash->{$evt}{dest_ip}}++ 	;
	# Protocol------------------------------------------------------------#
	$sids{Summary}{'Proto'}{$datahash->{$evt}{proto}}++	 	;
	# General counters----------------------------------------------------#
	$auditS{S}{Network}{Protocols}{'Flows Count'}{lc($datahash->{
	    $evt}{proto})}{$parserevt}++;
	$sids{Summary}{'Events Counter'}{$datahash->{$evt}{event_type}}++;
	$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Summary}{'Proto'}{
	    $datahash->{$evt}{proto}}++	;
	$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
	    $datahash->{$evt}{event_type}}{'Event Counter'}++;
	# Audit---------------------------------------------------------------#
	$auditS{S}{Assets}{Flows}{'Dest IP'}{'Flows Count'}{
	    $datahash->{$evt}{dest_ip}}{$parserevt}++;
	$auditS{S}{Events}{'Events Counter'}{$datahash->{
	    $evt}{event_type}}{$parserevt}++;
	my $cntTyp = "Event$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{
	    'Events'}{$datahash->{$evt}{event_type}}{'Event Counter'}";
	my $cnt = keys%$datahash;
	$sids{'Event Tracking'}{'Total Events'} = $cnt;
	## Event information--------------------------------------------------#
	if    ( $datahash->{$evt}{event_type} eq "alert" )
	{
	    $sids{Summary}{'Events Info'}{Alert}{Action}{$datahash->{
		$evt}{alert}{action}}++ ;
	    $sids{Summary}{'Events Info'}{Alert}{Signature}{$datahash->{
		$evt}{alert}{signature}}++;
	    $sids{Summary}{'Events Info'}{Alert}{Category}{$datahash->{
		$evt}{alert}{category}}++ ;
	    $sids{Summary}{'Events Info'}{Alert}{Severity}{$datahash->{
		$evt}{alert}{severity}}++ ;
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Summary}{
		$datahash->{$evt}{event_type}}{Action}{ 
		$datahash->{$evt}{alert}{action}}++;
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Summary}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}++;
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{$cntTyp}{
		'Timestamp'}   = $datahash->{$evt}{timestamp};
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{$cntTyp}{
		'Src IP'}   = $datahash->{$evt}{src_ip};
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{$cntTyp}{
		'Src port'} = $datahash->{$evt}{src_port};
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{$cntTyp}{
		'Dst IP'}   = $datahash->{$evt}{dest_ip};
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{$cntTyp}{
		'Dst port'} = $datahash->{$evt}{dest_port};
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{$cntTyp}{
		'Protocol'} = $datahash->{$evt}{proto};
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{$cntTyp}{
		'Action'} = $datahash->{$evt}{alert}{action};
	    $sids{'Event Tracking'}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{
		$datahash->{$evt}{src_ip}}{$evt}{
		'Timestamp'}   = $datahash->{$evt}{timestamp};
	    $sids{'Event Tracking'}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{
		$datahash->{$evt}{src_ip}}{$evt}{
		'Source IP'}   =  $datahash->{$evt}{src_ip};
	    $sids{'Event Tracking'}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{
		$datahash->{$evt}{src_ip}}{$evt}{
	    'Dest IP'}     =  $datahash->{$evt}{dest_ip};
	    $sids{'Event Tracking'}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{
		$datahash->{$evt}{src_ip}}{$evt}{
	    'Protocol'}    =  $datahash->{$evt}{proto};
	    $sids{'Event Tracking'}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{
		$datahash->{$evt}{src_ip}}{$evt}{
		'Action'} = $datahash->{$evt}{alert}{action};
	    $sids{'Event Tracking'}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{
		$datahash->{$evt}{src_ip}}{$evt}{
		'SignatureId'}=$datahash->{$evt}{alert}{signature_id};
	    ## Payload--------------------------------------------------------#
	    my $paypath =   "payload/sc_";
	    if ($datahash->{$evt}{src_port} &&
		$datahash->{$evt}{dest_port} )
	    {
		$paypath .= $datahash->{$evt}{src_ip}   . "_"  .
			    $datahash->{$evt}{src_port} . "_"  .
			    $datahash->{$evt}{dest_ip}  . "_"  .
			    $datahash->{$evt}{dest_port}. "_"  ;
		$sids{'Event Tracking'}{Events}{
		    $datahash->{$evt}{event_type}}{"Severity".
		    $datahash->{$evt}{alert}{severity}}{
		    $datahash->{$evt}{alert}{category}}{
		    $datahash->{$evt}{alert}{signature}}{
		    $datahash->{$evt}{src_ip}}{$evt}{
		    'Source Port'} =  $datahash->{$evt}{src_port};
		$sids{'Event Tracking'}{Events}{
		    $datahash->{$evt}{event_type}}{"Severity".
		    $datahash->{$evt}{alert}{severity}}{
		    $datahash->{$evt}{alert}{category}}{
		    $datahash->{$evt}{alert}{signature}}{
		    $datahash->{$evt}{src_ip}}{$evt}{
		    'Dest Port'}   =  $datahash->{$evt}{dest_port};
	    }
	    else
	    {
		$paypath .= $datahash->{$evt}{src_ip}   . "_"  .
			    $datahash->{$evt}{dest_ip}  . "_"  ;
	    }
	    $datahash->{$evt}{timestamp} =~ m/(.*)\.(.*)/ ;
	    my $ts   = $1;
	    my $usec = $2;
	    $ts =~ s/T//g;
	    my $date =  Time::Piece->strptime($ts,
			$CFG::options{tf_suricata});
	    my $epoch= $date->epoch;
	    $paypath .= $epoch . "." . $usec;
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{$cntTyp}{
		'Payload'} = $paypath;
	    $sids{'Event Tracking'}{Events}{
		$datahash->{$evt}{event_type}}{"Severity".
		$datahash->{$evt}{alert}{severity}}{
		$datahash->{$evt}{alert}{category}}{
		$datahash->{$evt}{alert}{signature}}{
		$datahash->{$evt}{src_ip}}{$evt}{
		'Payload'} = $paypath;
	    ## Audit----------------------------------------------------------#
	    $auditS{S}{Events}{'Events Info'}{Alert}{Action}{
		$datahash->{$evt}{alert}{action}}{$parserevt}++;
	    $auditS{S}{Events}{'Events Info'}{Alert}{Signature}{
		$datahash->{$evt}{alert}{signature}}{$parserevt}++;
	    $auditS{S}{Events}{'Events Info'}{Alert}{Category}{
		$datahash->{$evt}{alert}{category}}{$parserevt}++;
	    $auditS{S}{Events}{'Events Info'}{Alert}{Severity}{
		$datahash->{$evt}{alert}{severity}}{$parserevt}++;
	}
	else
	{
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{$datahash->{
		$evt}{event_type}}{List}{$cntTyp}{Timestamp}  =
		$datahash->{$evt}{timestamp};
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{$datahash->{
		$evt}{event_type}}{List}{$cntTyp}{'Src Port'} =
		$datahash->{$evt}{src_port};
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{$datahash->{
		$evt}{event_type}}{List}{$cntTyp}{'Dest IP'}  =
		$datahash->{$evt}{dest_ip};
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{$datahash->{
		$evt}{event_type}}{List}{$cntTyp}{'Dest Port'}=
		$datahash->{$evt}{dest_port};
	    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{$datahash->{
		$evt}{event_type}}{List}{$cntTyp}{Protocol}   =
		$datahash->{$evt}{proto};
	    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		$datahash->{$evt}{src_ip}}{$evt}{
		'Timestamp'}   = $datahash->{$evt}{timestamp};
	    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		$datahash->{$evt}{src_ip}}{$evt}{
		'Source IP'}   = $datahash->{$evt}{src_ip};
	    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		$datahash->{$evt}{src_ip}}{$evt}{
		'Source Port'} = $datahash->{$evt}{src_port};
	    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		$datahash->{$evt}{src_ip}}{$evt}{
		'Dest IP'}     = $datahash->{$evt}{dest_ip};
	    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		$datahash->{$evt}{src_ip}}{$evt}{
		'Dest Port'}   = $datahash->{$evt}{dest_port};
	    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		$datahash->{$evt}{src_ip}}{$evt}{
		'Protocol'}    = $datahash->{$evt}{proto};
	    if ( $datahash->{$evt}{event_type} eq "tls" )
	    {
		$sids{Summary}{'Events Info'}{Tls}{subject}{$datahash->{
		    $evt}{tls}{subject}}++;
		$sids{Summary}{'Events Info'}{Tls}{issuerdn}{$datahash->{
		    $evt}{tls}{issuerdn}}++;
		$sids{Summary}{'Events Info'}{Tls}{fingerprint}{$datahash->{
		    $evt}{tls}{fingerprint}}++ ;
		$sids{Summary}{'Events Info'}{Tls}{version}{$datahash->{
		    $evt}{tls}{version}}++;
		$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		    $datahash->{$evt}{event_type}}{List}{$cntTyp}{Subject}  =
		    $datahash->{$evt}{tls}{subject};
		$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		    $datahash->{$evt}{event_type}}{List}{$cntTyp}{IssuerDN} =
		$datahash->{$evt}{tls}{issuerdn};
		$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		    $datahash->{$evt}{event_type}}{List}{$cntTyp}{Fingerprint}=
		$datahash->{$evt}{tls}{fingerprint};
		$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		    $datahash->{$evt}{event_type}}{List}{$cntTyp}{Version}  =
		$datahash->{$evt}{tls}{version};
		$sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		    $datahash->{$evt}{src_ip}}{$evt}{'Subject'}     = 
		    $datahash->{$evt}{tls}{subject};
		$sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		    $datahash->{$evt}{src_ip}}{$evt}{'IssuerDN'}    = 
		    $datahash->{$evt}{tls}{issuerdn};
		$sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		    $datahash->{$evt}{src_ip}}{$evt}{'Fingerprint'} = 
		    $datahash->{$evt}{tls}{fingerprint};
		$sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		    $datahash->{$evt}{src_ip}}{$evt}{'Version'}     =
		    $datahash->{$evt}{tls}{version};
		$auditS{S}{Events}{'Events Info'}{Tls}{subject}{
		    $datahash->{$evt}{tls}{subject}}{$parserevt}++;
		$auditS{S}{Events}{'Events Info'}{Tls}{issuerdn}{
		    $datahash->{$evt}{tls}{issuerdn}}{$parserevt}++;
		$auditS{S}{Events}{'Events Info'}{Tls}{fingerprint}{
		    $datahash->{$evt}{tls}{fingerprint}}{$parserevt}++ ;
		$auditS{S}{Events}{'Events Info'}{Tls}{version}{
		    $datahash->{$evt}{tls}{version}}{$parserevt}++;
	    }
	    elsif ( $datahash->{$evt}{event_type} eq "dns" )
	    {
		$sids{Summary}{'Events Info'}{Dns}{type}{
		    $datahash->{$evt}{dns}{type}}++ ;
		$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		    $datahash->{$evt}{event_type}}{List}{$cntTyp}{Type} =
		    $datahash->{$evt}{dns}{type};
		$sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		    $datahash->{$evt}{src_ip}}{$evt}{'Type'}            = 
		    $datahash->{$evt}{dns}{type};
		$auditS{S}{Events}{'Events Info'}{Dns}{'Type'}{
		    $datahash->{$evt}{dns}{type}}{$parserevt}++ ;
		if ( $datahash->{$evt}{dns}{rrname} )
		{
		    $sids{Summary}{'Events Info'}{Dns}{rname}{$datahash->{
			$evt}{dns}{rrname}}++;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'rrname'} = $datahash->{$evt}{dns}{rrname};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'rrname'} = $datahash->{$evt}{dns}{rrname};
		    $auditS{S}{Domains}{$datahash->{$evt}{dns}{rrname}}{
			$datahash->{$evt}{src_ip}}{$parserevt}++;
		}
		if ( $datahash->{$evt}{dns}{rrtype} )
		{
		    $sids{Summary}{'Events Info'}{Dns}{rrtype}{$datahash->{
			$evt}{dns}{rrtype}}++ ;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'rrtype'} = $datahash->{$evt}{dns}{rrtype};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'rrtype'} = $datahash->{$evt}{dns}{rrtype};
		    $auditS{S}{Events}{'Events Info'}{Dns}{'Query Type'}{
			$datahash->{$evt}{dns}{rrtype}}{$parserevt}++;
		}
		if ( $datahash->{$evt}{dns}{rrdata} )
		{
		    $sids{Summary}{'Events Info'}{Dns}{rrdata}{$datahash->{
			$evt}{dns}{rrdata}}++;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'rrdata'} = $datahash->{$evt}{dns}{rrdata};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'rrdata'} = $datahash->{$evt}{dns}{rrdata};
		}
		if ( $datahash->{$evt}{dns}{ttl} )
		{
		    $sids{Summary}{'Events Info'}{Dns}{ttl}{$datahash->{
			$evt}{dns}{ttl}}++;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'TTL'} = $datahash->{$evt}{dns}{ttl};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'TTL'} = $datahash->{$evt}{dns}{ttl};
		    $auditS{S}{Events}{'Events Info'}{Dns}{Ttl}{
			$datahash->{$evt}{dns}{ttl}}{$parserevt}++;
		}
	    }
	    elsif ( $datahash->{$evt}{event_type} eq "http" )
	    {
		my $url;
		if ( $datahash->{$evt}{http}{hostname} &&
		     $datahash->{$evt}{http}{url})
		{
		    $sids{Summary}{'Events Info'}{Http}{Hostname}{$datahash->{
			$evt}{http}{hostname}}++ ;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'Hostname'}=$datahash->{$evt}{http}{hostname};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'Hostname'}=$datahash->{$evt}{http}{hostname};
		    $auditS{S}{Domains}{$datahash->{$evt}{http}{hostname}}{
			$datahash->{$evt}{src_ip}}{$parserevt}++;
		    $url = "http://$datahash->{$evt}{http}{hostname}/".
			  "$datahash->{$evt}{http}{url}";
		}
		elsif ( $datahash->{$evt}{dest_ip} &&
			$datahash->{$evt}{http}{url})
		{
		    $url = "http://$datahash->{$evt}{dest_ip}/".
			  "$datahash->{$evt}{http}{url}";
		}
		else
		{
		    $url = "";
		}
		if ( $url )
		{
		    tokenize($self,$url,$sids{Summary}{'Events Info'}{Http},
			$parserevt, 'Urls');
		    tokenize($self,$url,$auditS{S}{'Http Info'},
			$parserevt,'Urls');
		    tokenize($self, $url,
			$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{
			'Events'}{$datahash->{$evt}{event_type}}{List}{
			$cntTyp}, $parser, 'Urls');
		    tokenize($self, $url,
			$sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}, 
			$parser,'Urls');
		}
		if ( $datahash->{$evt}{http}{http_user_agent} )
		{
		    $datahash->{$evt}{timestamp} =~ m/(.*)\.(.*)/ ;
		    my $ts   = $1;
		    my $usec = $2;
		    $ts =~ s/T//g;
		    my $date =  Time::Piece->strptime($ts,
				$CFG::options{tf_suricata});
		    $ts   = $date->epoch;
		    getUserAgentInfo($self,
			$datahash->{$evt}{http}{'http_user_agent'},
			$sids{Summary}{'Events Info'}{Http}, $parserevt);
		    getUserAgentInfo($self,
			$datahash->{$evt}{http}{'http_user_agent'},
			$auditS{S}{'Http Info'}, $parserevt);
		    getUserAgentInfo($self,
			$datahash->{$evt}{http}{'http_user_agent'},
			$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{
			'Events'}{$datahash->{$evt}{event_type}}{List}{
			$cntTyp}, $parser);
		    getUserAgentInfo($self,
			$datahash->{$evt}{http}{'http_user_agent'},
			$sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt},
			$parser);
		    $auditSW{S}{$datahash->{$evt}{http}{'http_user_agent'}}{
			'Assets'}{$datahash->{$evt}{src_ip}}{$ts}++;
		    getSoftwareInfo($self, $auditSW{S}{$datahash->{
			$evt}{http}{http_user_agent}}, $datahash->{
			$evt}{http}{http_user_agent}, $parserevt);
		}
		if ( $datahash->{$evt}{http}{'http_content_type'} )
		{
		    $sids{Summary}{'Events Info'}{Http}{'Content types'}{
			$datahash->{$evt}{http}{'http_content_type'}}++ ;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		    $datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'Content type'} = $datahash->{$evt}{http}{
			'http_content_type'};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'Content type'} = $datahash->{$evt}{http}{
			'http_content_type'};
		    $auditS{S}{Events}{'Events Info'}{Http}{
			'Content types'}{$datahash->{$evt}{http}{
			'http_content_type'}}{$parserevt}++ ;
		}
		if ( $datahash->{$evt}{http}{http_refer} )
		{
		    $sids{Summary}{'Events Info'}{Http}{Referers}{$datahash->{
			$evt}{http}{http_refer}}++ ;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'Referer'} = $datahash->{$evt}{http}{'http_refer'};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'Referer'} = $datahash->{$evt}{http}{'http_refer'};
		    $auditS{S}{Events}{'Events Info'}{Http}{Referers}{
			$datahash->{$evt}{http}{http_refer}}{$parserevt}++;
		}
		if ( $datahash->{$evt}{http}{http_method} )
		{
		    $sids{Summary}{'Events Info'}{Http}{Methods}{
			$datahash->{$evt}{http}{http_method}}++ ;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'Method'} = $datahash->{$evt}{http}{http_method};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'Method'} = $datahash->{$evt}{http}{http_method};
		    $auditS{S}{Events}{'Events Info'}{Http}{Methods}{
			$datahash->{$evt}{http}{http_method}}{$parserevt}++;
		}
		if ( $datahash->{$evt}{http}{protocol} )
		{
		    $sids{Summary}{'Events Info'}{Http}{Protocols}{
			$datahash->{$evt}{http}{protocol}}++ ;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'Protocol'} = $datahash->{$evt}{http}{protocol};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'Protocol'} = $datahash->{$evt}{http}{protocol};
		    $auditS{S}{Events}{'Events Info'}{Http}{Protocols}{
			$datahash->{$evt}{http}{protocol}}{$parserevt}++ ;
		}
		if ( $datahash->{$evt}{http}{status} )
		{
		    $sids{Summary}{'Events Info'}{Http}{'Status codes'}{
			$datahash->{$evt}{http}{status}}++ ;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'Status code'} = $datahash->{$evt}{http}{'status'};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
		        'Status code'} = $datahash->{$evt}{http}{'status'};
		    $auditS{S}{Events}{'Events Info'}{Http}{'Status codes'}{
			$datahash->{$evt}{http}{status}}{$parserevt}++ ;
		}
	    }
	    elsif ( $datahash->{$evt}{event_type} eq "fileinfo" )
	    {
		if ( $datahash->{$evt}{fileinfo}{filename} )
		{
		    $sids{Summary}{'Events Info'}{File}{Filenames}{$datahash->{
			$evt}{fileinfo}{filename}}++ ;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'Filename'}=$datahash->{$evt}{fileinfo}{filename};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'Filename'} = $datahash->{$evt}{fileinfo}{filename};
		    $auditS{S}{Events}{'Events Info'}{File}{Filenames}{
			$datahash->{$evt}{fileinfo}{filename}}{
			$parserevt}++;
		}
		if ( $datahash->{$evt}{fileinfo}{stored} )
		{
		    $sids{Summary}{'Events Info'}{File}{Stored}{$datahash->{
			$evt}{fileinfo}{stored}}{$parserevt}++ ;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'Stored'} = $datahash->{$evt}{fileinfo}{stored};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'Stored'}   = $datahash->{$evt}{fileinfo}{stored};
		}
		if ( $datahash->{$evt}{fileinfo}{size} )
		{
		    $sids{Summary}{'Events Info'}{File}{Size}{$datahash->{
			$evt}{fileinfo}{size}}++ ;
		    $sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
			$datahash->{$evt}{event_type}}{List}{$cntTyp}{
			'Size'} = $datahash->{$evt}{fileinfo}{size};
		    $sids{'Event Tracking'}{Events}{$datahash->{$evt}{
			'event_type'}}{$datahash->{$evt}{src_ip}}{$evt}{
			'Size'}    = $datahash->{$evt}{fileinfo}{size};
		    $auditS{S}{Events}{'Events Info'}{File}{Size}{
			$datahash->{$evt}{fileinfo}{size}}{$parserevt}++;
		}
	    }
	    elsif ( $datahash->{$evt}{event_type} eq "ssh" )
	    {
		$sids{Summary}{'Events Info'}{Ssh}{Client}{'Protocol Version'}{
		    $datahash->{$evt}{ssh}{client}{proto_version}}++;
		$sids{Summary}{'Events Info'}{Ssh}{Client}{Software}{
		    $datahash->{$evt}{ssh}{client}{software_version}}++;
		$sids{Summary}{'Events Info'}{Ssh}{Server}{'Protocol Version'}{
		    $datahash->{$evt}{ssh}{server}{proto_version}}++;
		$sids{Summary}{'Events Info'}{Ssh}{Server}{Software}{
		    $datahash->{$evt}{ssh}{server}{software_version}}++;
		$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		    $datahash->{$evt}{event_type}}{List}{$cntTyp}{
		    'Ssh client'}{'Protocol version'}=$datahash->{$evt}{
		    'ssh'}{client}{'proto_version'};
		$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		    $datahash->{$evt}{event_type}}{List}{$cntTyp}{
		    'Ssh client'}{'Software'} = $datahash->{$evt}{
		    'ssh'}{client}{'software_version'};
		$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		    $datahash->{$evt}{event_type}}{List}{$cntTyp}{
		    'Ssh server'}{'Protocol version'}=$datahash->{$evt}{
		    'ssh'}{server}{'proto_version'};
		$sids{'IP Tracking'}{$datahash->{$evt}{src_ip}}{Events}{
		    $datahash->{$evt}{event_type}}{List}{$cntTyp}{
		    'Ssh server'}{'Software'}=$datahash->{$evt}{
		    'ssh'}{server}{'software_version'};
		$sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		    $datahash->{$evt}{src_ip}}{$evt}{'Ssh client'}{
		    'Protocol version'} = $datahash->{$evt}{ssh}{
		    'client'}{'proto_version'};
		$sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		    $datahash->{$evt}{src_ip}}{$evt}{'Ssh client'}{
		    'Software'} = $datahash->{$evt}{ssh}{
		    'client'}{'software_version'};
		$sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		    $datahash->{$evt}{src_ip}}{$evt}{'Ssh server'}{
		    'Protocol version'} = $datahash->{$evt}{ssh}{
		    'server'}{'proto_version'};
		$sids{'Event Tracking'}{Events}{$datahash->{$evt}{event_type}}{
		    $datahash->{$evt}{src_ip}}{$evt}{'Ssh server'}{
		    'Software'} = $datahash->{$evt}{ssh}{
		    'server'}{'software_version'};
		$auditS{S}{Events}{'Events Info'}{Ssh}{Client}{
		    'Protocol Version'}{$datahash->{$evt}{ssh}{client}{
		    'proto_version'}}{$parserevt}++;
		$auditS{S}{Events}{'Events Info'}{Ssh}{Client}{
		    'Software'}{$datahash->{$evt}{ssh}{client}{
		    'software_version'}}{$parserevt}++;
		$auditS{S}{Events}{'Events Info'}{Ssh}{Server}{
		    'Protocol Version'}{$datahash->{$evt}{ssh}{server}{
		    'proto_version'}}{$parserevt}++;
		$auditS{S}{Events}{'Events Info'}{Ssh}{Server}{
		    'Software'}{$datahash->{$evt}{ssh}{server}{
		    'software_version'}}{$parserevt}++;
	    }
	    else
	    {
		logMsgT($self,"$parser: Unknown event type ".
			"($datahash->{$evt}{event_type})",
			1, $CFG::options{log_file});
	    }
	}
    }
    # Payloads decoding
    # ------------------------------------------------------------------------#
    if ($CFG::options{'payload'} =~ m/(yes)|1/ )
    {
	my $paydir = "$outdir/payload";
	execute($self, "mkdir", $paydir);
	logMsgT($self,"Decoding payloads. Storing files into ($paydir)",
		       2, $CFG::options{log_file});
	if (opendir (DIR, $datadir) )
	{
	    my %payloads;
	    my $flag = 0;
	    while (my $file = readdir(DIR))
	    {
		next if ($file =~ m/^\./);
		if ( $file =~ m/unified2.alert\.[0-9]+/ )
		{
		    getPayloads($self, \%payloads,"$outdir/$file");
		    writePayloadFiles($self, \%payloads, $paydir, "sc_");
		    $flag = 1;
		}
	    }
	    if ( $flag == 0 )
	    {
		logMsgT($self,"No unified2 files within ($paydir)",
			    1, $CFG::options{log_file});
	    }
	    closedir(DIR);
	}
    }
    # -------------------------  End parsing process -------------------------#

    if    ( $query eq "json" )
    {
	$rec  = "\n{";
	$rec .= "\n\t\"Message\":\"Query  'string' is deprecated. ";
	$rec .= "Use 'hash' instead\",";
	$rec .= "\n\t\"Ex. Step1\": \"my %hash = ".
		"processHttpry('fname','file','hash')\",";
	$rec .= "\n\t\"Ex. Step2\":".
		"\"writeJsonFile('fname',\\%hash,'outfile')\"";
	$rec .= "\n}";
	return $rec;
    }
    elsif ( $query eq "hash" )
    {
        return %sids;
    }
    else
    {
	logMsgT($self,"Invalid query ($query)",	0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Parses Snort data.
## Syntax     : processSnortIds(CURRENT_FUNCTION, DATAFILE, QUERY,OUTDIR)
## OPTIONS    : QUERY	'hash'    : Returns a hash with parsing info.
##############################################################################
sub processSnortIds
{
    my ($caller, $datafile, $query, $outdir) = @_;
    my $self  = getFunctionName($caller,(caller(0))[3]);
    my $parser = "snortIds";
    my %sids  ; 
    my %event ; 
    my $rec   ; 
    my $payloadCnt = 0;

    # ------------------ Begin of Unified2 parsing process -------------------#
    my $sids  = get_snort_sids ("$CFG::options{path}/etc/sid-msg.map",
			       "$CFG::options{path}/etc/gen-msg.map");
    my $class = get_snort_classifications(
		"$CFG::options{path}/etc/classification.config");
    unless ( -f $datafile )
    {
	logMsgT($self,"Unable to open Snort unified 2 file ($datafile)",
		0, $CFG::options{log_file});
	return;
    }
    my $UF_Data  = openSnortUnified($datafile);
    unless ( $UF_Data )
    {
	logMsgT($self,"Snort unified 2 file ($datafile) could not be opened",
		0, $CFG::options{log_file});
	return;
    }
    while ( my $record = readSnortUnified2Record() )
    {
	# if record contains these fields, means that it's the event info rec.
	# Otherwise is the packet info record.
	if ( $record->{'generator_id'} && $record->{'signature_id'} &&
	     $record->{'signature_revision'} )
	{
	    my $msg = get_msg($sids, $record->{'generator_id'}	,
			      $record->{'signature_id'}		,
			      $record->{'signature_revision'})	;
	    my $cla = get_class($class, $record->{'classification_id'});
	    $event{"Event$record->{event_id}"}{signature} 	= $msg;
	    $event{"Event$record->{event_id}"}{'class'} 	= $cla;
	    $event{"Event$record->{event_id}"}{proto} 		=
				    $record->{protocol};
	    if ( $record->{ip_source} )
	    {
		$event{"Event$record->{event_id}"}{'src_ip'}   = 
		    dec2ip($self, $record->{ip_source});
	    }
	    elsif ( $record->{'in6_addr ip_source'} )
	    {
		$event{"Event$record->{event_id}"}{'src_ip'}   = 
		    $record->{'in6_addr ip_source'};
	    }
	    else
	    {
		$event{"Event$record->{event_id}"}{'dest_ip'}   = 
		    "unknown source";
	    }
	    if ( $record->{ip_destination} )
	    {
		$event{"Event$record->{event_id}"}{'dest_ip'}   = 
		    dec2ip($self, $record->{ip_destination});
	    }
	    elsif ( $record->{'in6_addr ip_destination'} )
	    {
		$event{"Event$record->{event_id}"}{'dest_ip'}   = 
		    $record->{'in6_addr ip_destination'};
	    }
	    else
	    {
		$event{"Event$record->{event_id}"}{'dest_ip'}   = 
		    "unknown destination";
	    }
	    if ( $record->{dport_icode} )
	    {
		$event{"Event$record->{event_id}"}{'dest_port'}	= 
				    $record->{dport_icode};
	    }
	    if ( $record->{sport_itype} )
	    {
		$event{"Event$record->{event_id}"}{'src_port'} 	= 
				    $record->{sport_itype};
	    }
	    $event{"Event$record->{event_id}"}{'priority'} 	= 
				    $record->{priority_id};
	    $event{"Event$record->{event_id}"}{'timestamp'} 	= 
		$record->{event_second}. ".". $record->{event_microsecond};
	}
	else
	{
	    $event{"Event$record->{event_id}"}{'payload_size'}=$record->{SIZE};
	    if ($CFG::options{'payload'} =~ m/(yes)|1/ )
	    {
		$event{"Event$record->{event_id}"}{'payload'} =
		xd $record->{raw_record}, {
		row   => 16, # print 10 bytes in a row
		cols  => 2,  # split in 2 column groups, separated with <hsp?>
		hsp   => 0,  # add 2 spaces between hex columns
		csp   => 0,  # add 1 space between char columns
		hpad  => 1,  # pad each hex byte with 1 space (ex: " 00" )
		cpad  => 0,  # pad each char byte with 1 space
		};
		$payloadCnt++;
	    }
	}
    }
    logMsgT($self," |-- Parsed ($payloadCnt) IDS events from $datafile",
	    2, $CFG::options{log_file});
    closeSnortUnified();
    # ------------------- End of Unified2 parsing process --------------------#
    # -------------------  Begin parsing process --------------------#
    foreach my $evt (keys%event)
    {
	my $paypath =   "payload/sn_";
	$sids{Summary}{'Protocol'}{$event{$evt}{proto}}++;
	$sids{'IP Tracking'}{$event{$evt}{src_ip}}{
	    "Priority $event{$evt}{priority}"}{$event{$evt}{class}}{
	    $event{$evt}{signature}}{$evt}{Protocol}    = 
	    $event{$evt}{proto};
	$sids{'Evt Tracking'}{'Alerts'}{"Priority $event{$evt}{priority}"}{
	    $event{$evt}{class}}{$event{$evt}{signature}}{$event{
	    $evt}{src_ip}}{$evt}{Protocol} = $event{$evt}{proto};
	$auditS{S}{Network}{Protocols}{'Flows Count'}{
	    getProto($self,$event{$evt}{proto})}{$parser}++;

	$sids{Summary}{'Source IP'}{$event{$evt}{src_ip}}++;
	$sids{'IP Tracking'}{$event{$evt}{src_ip}}{
	    "Priority $event{$evt}{priority}"}{$event{$evt}{class}}{
	    $event{$evt}{signature}}{$evt}{'Source IP'} =
	    $event{$evt}{src_ip};
	$sids{'Evt Tracking'}{'Alerts'}{"Priority $event{$evt}{priority}"}{
	    $event{$evt}{class}}{$event{$evt}{signature}}{$event{
	    $evt}{src_ip}}{$evt}{'Source IP'} = $event{$evt}{src_ip};
	$paypath .= $event{$evt}{src_ip} . "_"  ;

	$auditS{S}{Assets}{Flows}{'Source IP'}{'Flows Count'}{
	    $event{$evt}{src_ip}}{$parser}++;
	if ( $event{$evt}{src_port} )
	{
	    $sids{Summary}{'Source port'}{$event{$evt}{src_port}}++;
	    $auditS{S}{Assets}{Flows}{'Source Port'}{'Flows Count'}{
		$event{$evt}{src_port}}{$parser}++;
	    $sids{'IP Tracking'}{$event{$evt}{src_ip}}{
		"Priority $event{$evt}{priority}"}{
		$event{$evt}{class}}{$event{$evt}{signature}}{
		$evt}{'Source port'} = $event{$evt}{src_port};
	    $sids{'Evt Tracking'}{'Alerts'}{
		"Priority $event{$evt}{priority}"}{$event{
		$evt}{class}}{$event{$evt}{signature}}{$event{
		$evt}{src_ip}}{$evt}{'Source port'} = 
		$event{$evt}{src_port};
	    $paypath .= $event{$evt}{src_port} . "_"  ;
	}
	$sids{Summary}{'Destination IP'}{$event{$evt}{dest_ip}}++;
	$auditS{S}{Assets}{Flows}{'Dest IP'}{'Flows Count'}{
	    $event{$evt}{dest_ip}}{$parser}++;
	$sids{'IP Tracking'}{$event{$evt}{src_ip}}{
	    "Priority $event{$evt}{priority}"}{
	    $event{$evt}{class}}{$event{$evt}{signature}}{
	    $evt}{'Destination IP'}	 = $event{$evt}{dest_ip};
	$sids{'Evt Tracking'}{'Alerts'}{
	    "Priority $event{$evt}{priority}"}{$event{
	    $evt}{class}}{$event{$evt}{signature}}{$event{$evt}{src_ip}}{
	    $evt}{'Destination IP'}	 = $event{$evt}{dest_ip};
	$paypath .= $event{$evt}{dest_ip} . "_"  ;
	if ( $event{$evt}{dest_port} )
	{
	    $sids{Summary}{'Destination port'}{$event{$evt}{dest_port}}++;
	    $auditS{S}{Assets}{Flows}{'Dest Port'}{'Flows Count'}{
		$event{$evt}{dest_port}}{$parser}++;
	    $sids{'IP Tracking'}{$event{$evt}{src_ip}}{
		"Priority $event{$evt}{priority}"}{
		$event{$evt}{class}}{$event{$evt}{signature}}{
		$evt}{'Destination port'} = $event{$evt}{dest_port};
	    $sids{'Evt Tracking'}{'Alerts'}{
		"Priority $event{$evt}{priority}"}{$event{
		$evt}{class}}{$event{$evt}{signature}}{$event{
		$evt}{src_ip}}{$evt}{'Destination port'} =
		$event{$evt}{dest_port};
	    $paypath .= $event{$evt}{dest_port} . "_"  ;
	}
	$paypath .= "$event{$evt}{timestamp}";
	$sids{'IP Tracking'}{$event{$evt}{src_ip}}{
	    "Priority $event{$evt}{priority}"}{
	    $event{$evt}{class}}{$event{$evt}{signature}}{
	    $evt}{Payload} = $paypath ;
	$sids{'IP Tracking'}{$event{$evt}{src_ip}}{
	    "Priority $event{$evt}{priority}"}{
	    $event{$evt}{class}}{$event{$evt}{signature}}{
	    $evt}{'Payload size'} = $event{$evt}{payload_size} ;
	$sids{'Evt Tracking'}{'Alerts'}{
	    "Priority $event{$evt}{priority}"}{$event{
	    $evt}{class}}{$event{$evt}{signature}}{$event{
	    $evt}{src_ip}}{$evt}{payload} = $paypath;
	$sids{Summary}{'Priority'}{$event{$evt}{priority}}++;
	$sids{Summary}{'Signature'}{$event{$evt}{signature}}++;
	$sids{Summary}{'Classification'}{$event{$evt}{class}}++;
	$auditS{S}{Events}{'Events Info'}{Alert}{Severity}{
	    $event{$evt}{priority}}{$parser}++;
	$auditS{S}{Events}{'Events Info'}{Alert}{Signature}{
	    $event{$evt}{signature}}{$parser}++;
	$auditS{S}{Events}{'Events Info'}{Alert}{Category}{
	    $event{$evt}{class}}{$parser}++;
	if ( $event{$evt}{payload} )
	{
	    my $content = "Payload size: $event{$evt}{payload_size}\n";
	    $content   .= "Payload data:\n$event{$evt}{payload}";
	    saveContent($self, $content, "$outdir/$paypath");
	}
    }
    # -------------------  End parsing process ----------------------#

    if    ( $query eq "json" )
    {
	$rec  = "\n{";
	$rec .= "\n\t\"Message\":\"Query  'string' is deprecated. ";
	$rec .= "Use 'hash' instead\",";
	$rec .= "\n\t\"Ex. Step1\": \"my %hash = ".
		"processHttpry('fname','file','hash')\",";
	$rec .= "\n\t\"Ex. Step2\":".
		"\"writeJsonFile('fname',\\%hash,'outfile')\"";
	$rec .= "\n}";
	return $rec;
    }
    elsif ( $query eq "hash" )
    {
        return %sids;
    }
    else
    {
	logMsgT($self,"Invalid query ($query)",	0, $CFG::options{log_file});
	return;
    }
}
#############################################################################
## Description: Parses BRO data.
## Syntax     : processBro(CURRENT_FUNCTION, DATAFILE, MODE, QUERY,OUTDIR)
## OPTIONS    : QUERY	'hash'    : Returns a hash with parsing info.
##############################################################################
sub processBro
{
    my ($caller, $datadir, $query, $outdir) = @_;
    my $self   = getFunctionName($caller,(caller(0))[3]);
    my $parser = 'bro';
    my %bro    ; 
    my $rec    ; 
    my $evtCnt = 0;
    my %noField;
    logMsgT($self," |-- Reading Bro log directory ($datadir)",
	    2, $CFG::options{log_file});
    unless ( opendir (DIR, $datadir) )
    {
	logMsgT($self,"Unable to read Bro logdir ($datadir)",
		0, $CFG::options{log_file});
	return;
    }
    #**************************** Begin file parsing *************************#
    while (my $name = readdir(DIR))
    {
	next if ( $name =~ m/(^\.|packet_filter.log|reporter.log)/ );
	my $file = "$datadir/$name";
	logMsgT($self," |-- Reading Bro logfile ($file)",
		2, $CFG::options{log_file});
	$name =~ m/(.*)\.log/;
	my $eid = $1;
	if ( open (FH_BROLOG, $file) )
	{
	    my $fs;
	    my $ss;
	    my @field;
	    my $cnt = 0;
	    while ( <FH_BROLOG> )
	    {
		my $asset;
		my $ts;
		if ( $_ =~ m/^#/ )
		{
		    chomp();
		    if ( $_ =~ m/^#separator (.*)/ )
		    {
			$fs = $1;
		    }
		    elsif ( $_ =~ m/^#set_separator$fs(.*)/ )
		    {
			$ss = $1;
		    }
		    elsif ( $_ =~ m/^#fields(.*)/ )
		    {
			#%field = getFields($self,$1,$fs);
			@field = split(/$fs/,$1);
			shift(@field);
		    }
		}
		else
		{
		    $cnt++;
		    my @line = split(/$fs/,$_);
		    # First two fields are out of the loop because:
		    # - Summary uses from 0 to @field
		    # - EVT Traking uses from 2 to @field
		    # Thus, it's better to manually take 0&1 fields and
		    # create a single loop from 2 to @fields, instead of
		    # using a loop from 0 to @field and use 'if' to filter
		    # out first two fields.
		    $bro{Summary}{$eid}{$field[0]}{$line[0]}++;
		    $bro{Summary}{$eid}{$field[1]}{$line[1]}++;
		    $bro{'Evt Tracking'}{$line[1]}{$eid}{$field[0]} =
			$line[0];
		     
		    for (my $i=2; $i<@field; $i++)	# Others
		    {
			# Extract subfields from comma-separated fields 
			# ------------------------------------------------#
			if ( $field[$i] =~ m/s$/        &&
			     $field[$i] !~ m/(byt|pkt)/  )
			{
			    my @flds = split($ss, $line[$i]);
			    foreach my $fl ( @flds )
			    {
				$fl =~ s/\..*//;
				$bro{Summary}{$eid}{$field[$i]}{$fl}++;
			    }
			    # Special handling for files UID related with
			    # Bro events (files.log) 
			    # ------------------------------------------------#
			    if ( $field[$i] =~ 'conn_uids' )
			    {
				my @uids = split(/$ss/,$line[4]);
				foreach my $uid ( @uids )
				{
				    for (my $i=0; $i<@field; $i++)
				    {
					next if ( $i == 4 ); # skip ConnUID
					$bro{'Evt Tracking'}{$uid}{$eid}{
					    $line[1]}{$field[$i]} = $line[$i];
				    }
				}
			    }
			}
			# General cases #
			# ------------------------------------------------#
			else
			{
			    $bro{Summary}{$eid}{$field[$i]}{$line[$i]}++;
			    $bro{'Evt Tracking'}{$line[1]}{$eid}{
				$field[$i]} = $line[$i];
			    # the 'if' block will catch SRCIP field which
			    # is always before auditing fields
			    if ( $field[$i] eq 'id.orig_h' )
			    {
				$asset = $line[$i];
			    }
			    elsif ( $field[$i] eq 'user_agent' ||
				  $eid eq 'ssh' &&
				   $field[$i] eq 'client'    ||
				  $eid eq 'ssh' &&
				   $field[$i] eq 'server'    
				)
			    {
				$auditSW{S}{$line[$i]}{Assets}{$asset}{
				    $line[0]}++;
				getSoftwareInfo($self, $auditSW{S}{
				   $line[$i]}, $line[$i], $parser);
			    }
			}
		    }
		}
	    }
	    close(FH_BROLOG);
	    foreach my $nof (keys%noField)
	    {
		logMsgT($self,"Unknown field ($nof) has been ignored ".
		    "($noField{$nof}) times",1, $CFG::options{log_file});
	    }
	    logMsgT($self," |-- Parsed ($cnt) Bro events from ($file)", 
			   2, $CFG::options{log_file});
	}
	else
	{
	    logMsgT($self,"Unable to read Bro logfile ($file)",
		    0, $CFG::options{log_file});
	}
    }
    closedir(DIR);
    #**************************** END file parsing ***************************#

    if    ( $query eq "json" )
    {
	$rec  = "\n{";
	$rec .= "\n\t\"Message\":\"Query  'string' is deprecated. ";
	$rec .= "Use 'hash' instead\",";
	$rec .= "\n\t\"Ex. Step1\": \"my %hash = ".
		"processHttpry('fname','file','hash')\",";
	$rec .= "\n\t\"Ex. Step2\":".
		"\"writeJsonFile('fname',\\%hash,'outfile')\"";
	$rec .= "\n}";
	return $rec;
    }
    elsif ( $query eq "hash" )
    {
        return %bro;
    }
    else
    {
	logMsgT($self,"Invalid query ($query)",	0, $CFG::options{log_file});
    }
}
#############################################################################
## Description: Parses ArgusFlow data.
## Syntax     : processArgusFlow(CURRENT_FUNCTION, DATAFILE, MODE, QUERY,OUTDIR)
## OPTIONS    : QUERY	'hash'    : Returns a hash with parsing info.
##############################################################################
sub processArgusFlow
{
    my ($caller, $datafile, $query, $outdir) = @_;
    my $self   = getFunctionName($caller,(caller(0))[3]);
    my $parser = "argus";
    my %argus  ; 
    my $rec    ;
    my $tmpCnt ;

    unless ( open(FH_ARGUS,$datafile) )
    {
	logMsgT($self,"Unable to open log file ($datafile)",
		0, $CFG::options{log_file});
	return;
    }
    my $header = <FH_ARGUS>;
    my @homenet  = split(",",$CFG::options{home_net});
    my $in_homenet = subnet_matcher(@homenet);
    #**************************** Begin file parsing *************************#
    while(<FH_ARGUS>)
    {
	chomp();
	my @line   = split(/,/,$_);
	my $flowid ;
	if ( $in_homenet->($line[1]) )
	{
	    if ( $in_homenet->($line[3]) )
	    {
		$flowid = "Internal-Internal";
	    }
	    else
	    {
		$flowid = "Internal-External";
	    }
	}
	else
	{
	    if ( $in_homenet->($line[3]) )
	    {
		$flowid = "External-Internal";
	    }
	    else
	    {
		$flowid = "External-External";
	    }
	}
	$line[7] = $line[7] / 1048576; # convert Bytes to MB
	# Summary
	# ----------------------------------------------------------------#
	$argus{Summary}{'Talkers Interaction'}{
	    'Flows Count'}{$flowid}    ++;
	$argus{Summary}{'Talkers Interaction'}{
	    'Packets Count'}{$flowid}  += $line[6];
	$argus{Summary}{'Talkers Interaction'}{
	    'Bandwith(MB)'}{$flowid}   += $line[7];
	$argus{Summary}{'Talkers Interaction'}{
	    'Track'}{$flowid}{$line[0]}{$line[1]}{$line[3]} ++;
	$argus{Summary}{Flows}{Protocols}{
	    'Flows Count'}{$line[0]}   ++;
	$argus{Summary}{Flows}{Protocols}{
	    'Packets Count'}{$line[0]} += $line[6];
	$argus{Summary}{Flows}{Protocols}{
	    'Bandwith(MB)'}{$line[0]}  += $line[7];
	$argus{Summary}{Flows}{'Source IP'}{
	    'Flows count'}{$line[1]}   ++;
	$argus{Summary}{Flows}{'Source IP'}{
	    'Packets Count'}{$line[1]} += $line[6];
	$argus{Summary}{Flows}{'Source IP'}{
	    'Bandwith(MB)'}{$line[1]}  += $line[7];
	$argus{Summary}{Flows}{'Source Port'}{
	    'Flows Count'}{$line[2]}   ++;
	$argus{Summary}{Flows}{'Source Port'}{
	    'Packets Count'}{$line[2]} += $line[6];
	$argus{Summary}{Flows}{'Source Port'}{
	    'Bandwith(MB)'}{$line[2]}  +=$line[7];
	$argus{Summary}{Flows}{'Dest IP'}{
	    'Flows Count'}{$line[3]}   ++;
	$argus{Summary}{Flows}{'Dest IP'}{
	    'Packets Count'}{$line[3]} += $line[6];
	$argus{Summary}{Flows}{'Dest IP'}{
	    'Bandwith(MB)'}{$line[3]}  += $line[7];
	$argus{Summary}{Flows}{'Dest Port'}{
	    'Flows Count'}{$line[4]}   ++ ;
	$argus{Summary}{Flows}{'Dest Port'}{
	    'Packets Count'}{$line[4]} += $line[6];
	$argus{Summary}{Flows}{'Dest Port'}{
	    'Bandwith(MB)'}{$line[4]} += $line[7];
	# Tracking
	# ----------------------------------------------------------------#
	$argus{Tracking}{$line[1]}{Summary}{Protocols}{$line[0]} 	++;
	$argus{Tracking}{$line[1]}{Summary}{'Flow Interaction'}{$flowid}++;
	$argus{Tracking}{$line[1]}{Summary}{'Target Hosts'}{$line[3]}   ++;
	$argus{Tracking}{$line[1]}{Summary}{'Target Ports'}{$line[4]}   ++;
	$argus{Tracking}{$line[1]}{Summary}{'Packets'}	    += $line[6];
	$argus{Tracking}{$line[1]}{Summary}{'Bandwith(MB)'} += $line[7];
	$argus{Tracking}{$line[1]}{'Flows'}{$flowid}{$line[0]}{$line[3]}{
	    $line[4]}{$line[8]}{$line[9]}{Packets}           = $line[6];
	$argus{Tracking}{$line[1]}{'Flows'}{$flowid}{$line[0]}{$line[3]}{
	    $line[4]}{$line[8]}{$line[9]}{'Bandwith(MB)'}    = $line[7];
	$argus{Tracking}{$line[1]}{'Flows'}{$flowid}{$line[0]}{$line[3]}{
	    $line[4]}{ $line[8]}{$line[9]}{'Source Port'}    = $line[2];
	# Audit
	# ----------------------------------------------------------------#
	$auditS{S}{'Interaction'}{'Flows Count'}{$flowid}{
	    $parser}  ++;
	$auditS{S}{'Interaction'}{'Packets Count'}{$flowid}{
	    $parser}  += $line[6];
	$auditS{S}{'Interaction'}{'Bandwith(MB)'}{$flowid}{
	    $parser}  +=$line[7];
	$auditS{S}{'Interaction'}{Track}{
	    $flowid}{$line[0]}{$line[1]}{$line[3]}{$parser} ++;
	$auditS{S}{Network}{Protocols}{'Flows Count'}{$line[0]}{
	    $parser}  ++;
	$auditS{S}{Network}{Protocols}{'Packets Count'}{$line[0]}{
	    $parser}  += $line[6];
	$auditS{S}{Network}{Protocols}{'Bandwith(MB)'}{$line[0]}{
	    $parser}  += $line[7];
	$auditS{S}{Assets}{Flows}{'Source IP'}{'Flows Count'}{$line[1]}{
	    $parser}  ++;
	$auditS{S}{Assets}{Flows}{'Source IP'}{'Packets Count'}{$line[1]}{
	    $parser}  += $line[6];
	$auditS{S}{Assets}{Flows}{'Source IP'}{'Bandwith(MB)'}{$line[1]}{
	    $parser}  += $line[7];
	$auditS{S}{Assets}{Flows}{'Source Port'}{'Flows Count'}{$line[2]}{
	    $parser}  ++;
	$auditS{S}{Assets}{Flows}{'Source Port'}{'Packets Count'}{$line[2]}{
	    $parser}  += $line[6];
	$auditS{S}{Assets}{Flows}{'Source Port'}{'Bandwith(MB)'}{$line[2]}{
	    $parser}  += $line[7];
	$auditS{S}{Assets}{Flows}{'Dest IP'}{'Flows Count'}{$line[3]}{
	    $parser}  ++;
	$auditS{S}{Assets}{Flows}{'Dest IP'}{'Packets Count'}{$line[3]}{
	    $parser}  += $line[6];
	$auditS{S}{Assets}{Flows}{'Dest IP'}{'Bandwith(MB)'}{$line[3]}{
	    $parser}  += $line[7];
	$auditS{S}{Assets}{Flows}{'Dest Port'}{'Flows Count'}{$line[4]}{
	    $parser}  ++ ;
	$auditS{S}{Assets}{Flows}{'Dest Port'}{'Packets Count'}{$line[4]}{
	    $parser}  += $line[6];
	$auditS{S}{Assets}{Flows}{'Dest Port'}{'Bandwith(MB)'}{$line[4]}{
	    $parser}  += $line[7];
	###################################################################
    }
    close(FH_ARGUS);
    #***************************** END file parsing **************************#

    if    ( $query eq "json" )
    {
	$rec  = "\n{";
	$rec .= "\n\t\"Message\":\"Query  'string' is deprecated. ";
	$rec .= "Use 'hash' instead\",";
	$rec .= "\n\t\"Ex. Step1\": \"my %hash = ".
		"processHttpry('fname','file','hash')\",";
	$rec .= "\n\t\"Ex. Step2\":".
		"\"writeJsonFile('fname',\\%hash,'outfile')\"";
	$rec .= "\n}";
	return $rec;
    }
    elsif ( $query eq "hash" )
    {
        return %argus;
    }
    else
    {
	logMsgT($self,"Invalid query ($query)",	0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Executes processing parsers and generates JSON files
## Syntax     : processDataset($CURRENT_FUNCTION, $LOGDIR, $TOOLSET, $OUTDIR)
##############################################################################
sub processDataset
{
    my ($caller, $instance_logdir, $toolset, $outdir) = @_;
    my $self = getFunctionName($caller,(caller(0))[3]);
    my %datahash;
    unless ($instance_logdir && $outdir)
    {
	unless ($instance_logdir)
	{
	    logMsgT($self,"Empty instance directory to process dataset",
			0,$CFG::options{log_file});
	}
	unless ($outdir)
	{
	    logMsgT($self,"Empty output directory to dump processed dataset",
			0,$CFG::options{log_file});
	}
	return;
    }
    logMsgT($self,"Processing dataset of instance ($instance_logdir).",
		  2,$CFG::options{log_file});
    if ( -d $outdir )
    {
	my $timeid = time;
	my $newout = "$CFG::options{dvm_web_dir}/instance\_$timeid";
	if ($CFG::args{log_dir})
	{
	    logMsgT($self,"JSON output directory ($outdir) exists already. " .
		    "Output directory will be ($newout)",
		    1,$CFG::options{log_file});
	}
	else
	{
	    logMsgT($self,"Output directory will be ($newout)",
		    2,$CFG::options{log_file});
	}
	$outdir = $newout;
    }
    else
    {
	logMsgT($self,"Output directory will be ($outdir)",
		2,$CFG::options{log_file});
    }
    execute($self,"mkdir", $outdir);
    execute($self,"cp","$CFG::options{dvm_web_dir}/json/summary|$outdir");
    execute($self,"cp","$CFG::options{dvm_web_dir}/json/view1|$outdir");
    execute($self,"cp","$CFG::options{dvm_web_dir}/json/view2|$outdir");
    execute($self,"cp","$CFG::options{dvm_web_dir}/json/theme|$outdir");
    execute($self,"cp","$CFG::options{dvm_web_dir}/json/.htaccess|$outdir");
    if ( $CFG::options{cap_file} )
    {
	insertContent($self, "$outdir/.htaccess", "$outdir/.htaccess",
		      $CFG::options{cap_file}, "SOURCE_DATASET"); 
    }
    elsif ( $CFG::options{instance_dir} )
    {
	insertContent($self, "$outdir/.htaccess", "$outdir/.htaccess",
		      $CFG::options{instance_dir}, "SOURCE_DATASET"); 
    }
    $datahash{"PNAF_TITLE"}   	       = "PNAF Dataset";
    $datahash{"ARGUSFLOWS_TITLE"}      = "ARGUS FLOW Data";
    $datahash{"P0FS_TITLE"}   	       = "P0F Data";
    $datahash{"PRADSS_TITLE"} 	       = "PRADS Data";
    $datahash{"SNORTAPPIDS_TITLE"}     = "SNORT OpenAppID Data";
    $datahash{"HTTPRYS_TITLE"}	       = "HTTPRY Data";
    $datahash{"TCPDSTATS_TITLE"}       = "TCPDSTAT Data";
    $datahash{"SURICATAIDSS_TITLE"}    = "SURICATA Data";
    $datahash{"SNORTIDSS_TITLE"}       = "SNORT IDS Data";
    $datahash{"BROS_TITLE"}            = "BRO Data";
    foreach my $tool (@{$toolset})
    {
	next if ( validateParser($self, $tool) == 0 );
	loadParser($self,$tool,\%datahash,$instance_logdir,$outdir);
    }
    my @outdata = split(",",$CFG::options{out_dataset});
    foreach my $out ( @outdata )
    {
	if ( $out eq "all" )
	{
	    createJsonTreeGroup($self, "dataset", \%datahash, $outdir);
	}
	elsif ( $out eq "audit" )
	{
	    if ( $CFG::options{cap_file} )
	    {
		$auditS{S}{'Capture Info'}{'Capture File'} =
		    $CFG::options{cap_file};
	    }
	    elsif ( $CFG::options{instance_dir} )
	    {
		$auditS{S}{'Capture Info'}{'Instance Directory'} =
		    $CFG::options{instance_dir};
	    }
	    if ( $CFG::options{home_net} )
	    {
		$auditS{S}{'Capture Info'}{'Home net'}= $CFG::options{home_net};
	    }
	    else
	    {
		$auditS{S}{'Capture Info'}{'Home net'}= "Undefined";
	    }
	    $auditOUT{DIC} = {};
	    $auditOUT{BLI} = {};
	    $auditOUT{BLD} = {};
	    $auditSW{SID}  = {};
	    getSoftwareAuditIds($self, $auditSW{S}, $auditSW{SID});
	    auditSoftware($self, $auditSW{SID}, $auditOUT{DIC},
			  $CFG::options{audit_dict});
	    auditBlackList($self, $auditS{S}{Interaction}{Track},
			   $auditOUT{BLI}, 'BLI');
	    auditBlackList($self, $auditS{S}{Domains},$auditOUT{BLD}, 'BLD');
	    writeJsonFile($self, $auditSW{S},"$outdir/software.json");
	    createJsonTreeGroup($self, "auditSummary" , \%auditS  , $outdir);
	    createJsonTreeGroup($self, "auditSoftware", \%auditSW , $outdir);
	    createJsonTreeGroup($self, "auditOutput"  , \%auditOUT, $outdir);
	    createJsonTreeGroup($self, "auditTracking", \%auditT  , $outdir);
	    createJsonTreeView1($self, "PNAF\_AUDIT\_(SUMMARY)",
				encode_json $auditS{S},$outdir);
	    createJsonTreeView1($self, "PNAF\_AUDIT\_(SOFTWARE)",
				encode_json $auditSW{S},$outdir);
	}
    }
}
##############################################################################
## Description: Loads a parser of a specified tool and fills the passed hash
## Syntax     : loadParser($CURRENT_FUNCTION,$TOOL,$MODE,\%HASH,$IDIR,$ODIR )
##############################################################################
sub loadParser
{
    my ($caller, $tool, $hash, $instance_dir, $outdir) = @_;
    my $self = getFunctionName($caller,(caller(0))[3]);
    my %tool_hash;
    logMsgT($self,"Loading Parser: ($tool)", 2, $CFG::options{log_file});
    if ( $tool eq "bro" )
    {
	%tool_hash = $processTool{$tool}->($self, "$instance_dir/bro",
				     "hash", $outdir);
    }
    elsif ( $tool eq "suricataEve" )
    {
	%tool_hash = $processTool{$tool}->($self, "$instance_dir",
				     "hash", $outdir);
    }
    else
    {
	%tool_hash = $processTool{$tool}->($self, "$instance_dir/$tool.log",
				     "hash", $outdir);
    }
    writeJsonFile($self, \%tool_hash,"$outdir/$tool.json");
    createJsonTreeView1($self, "PNAF\_$tool",
			encode_json \%tool_hash,$outdir);
    $hash->{$tool} = \%tool_hash;
}
##############################################################################
## Description: Extracts Information from a given string 
## Syntax     : getSoftwareInfo($CURRENT_FUNCTION, $HASHREF, $DATA, $PARSER)
##############################################################################
sub getSoftwareInfo
{
    my ($caller, $datahash, $data, $parser) = @_;
    my $self = getFunctionName($caller,(caller(0))[3]);
    if ( $data  =~ m/^(Mozilla|Opera|Dalvik|MacOS|Holo Launcher)\// )
    {
	 getUserAgentInfo($self, $data, $datahash, $parser);
    }
    else
    {
	tokenize($self, $data, $datahash,$parser, 'Software');
    }
}
##############################################################################
## Description: Extracts Information from a given string 
## Syntax     : getSoftwareAuditIds($CURRENT_FUNCTION, $HASHREF )
##############################################################################
sub getSoftwareAuditIds
{
    my ($caller, $datahash, $sidhash) = @_;
    my $self = getFunctionName($caller,(caller(0))[3]);
    foreach my $data (keys%$datahash)
    {
	if ( $datahash->{$data}{Software} )
	{
	    if ( $datahash->{$data}{'Software'}{'Terms'}{'alpha'}{'word'}    &&
		 $datahash->{$data}{'Software'}{'Terms'}{'alpha'}{'alphanum'}&&
		 $datahash->{$data}{'Software'}{'Terms'}{'alpha'}{'number'} )
	    {
		foreach my $ver (keys$datahash->{$data}{'Software'}{
				 'Terms'}{'alpha'}{'alphanum'})
		{
		    next unless ( $ver =~ m/[\d+\.]\.+/ );
		    $ver = lc($ver);
		    foreach my $prod (keys$datahash->{$data}{'Software'}{
				     'Terms'}{'alpha'}{'word'})
		    {
			next unless ($prod =~ m/....*/);
			$prod = lc($prod);
			$datahash->{$data}{'AuditIDs'}{"$prod$ver"}++;
			foreach my $asset (keys$datahash->{$data}{'Assets'})
			{
			    $sidhash->{"$prod$ver"}{$asset}++;
			}
		    }
		}
		foreach my $prod (keys$datahash->{$data}{'Software'}{
				 'Terms'}{'alpha'}{'word'})
		{
		    next unless ($prod =~ m/....*/);
		    $prod =~ s/server/_server/i;
		    $prod = lc($prod);
		    foreach my $ver (keys$datahash->{$data}{'Software'}{
				     'Terms'}{'alpha'}{'number'})
		    {
			next unless ($ver =~ m/...*/);
			$ver = "_$ver";
			foreach my $sub (keys$datahash->{$data}{'Software'}{
					 'Terms'}{'alpha'}{'alphanum'})
			{
			    $sub = "_$sub";
			    $sub = lc($sub);
			    $datahash->{$data}{'AuditIDs'}{"$prod$ver$sub"}++;
			    foreach my $as (keys$datahash->{$data}{'Assets'})
			    {
				$sidhash->{"$prod$ver$sub"}{$as}++;
			    }
			}
		    }
		}
	    }
	    elsif ( $datahash->{$data}{'Software'}{'Terms'}{'alpha'}{'word'} &&
		 $datahash->{$data}{'Software'}{'Terms'}{'alpha'}{'number'} )	
	    {
		foreach my $prod (keys$datahash->{$data}{'Software'}{
				 'Terms'}{'alpha'}{'word'})
		{
		    next unless ($prod =~ m/....*/);
		    $prod =~ s/server/_server/i;
		    $prod = lc($prod);
		    foreach my $ver (keys$datahash->{$data}{'Software'}{
				     'Terms'}{'alpha'}{'number'})
		    {
			next unless ($ver =~ m/...*/);
			$ver = "_$ver";
			$datahash->{$data}{'AuditIDs'}{"$prod$ver"}++;
			foreach my $asset (keys$datahash->{$data}{'Assets'})
			{
			    $sidhash->{"$prod$ver"}{$asset}++;
			}
		    }
		}
	    }
	    elsif ( $datahash->{$data}{'Software'}{'Terms'}{'alpha'}{'word'} &&
		 $datahash->{$data}{'Software'}{'Terms'}{'alpha'}{'alphanum'} )	
	    {
		foreach my $ver (keys$datahash->{$data}{'Software'}{
				 'Terms'}{'alpha'}{'alphanum'})
		{
		    next unless ( $ver =~ m/....*/ );
		    $ver = lc($ver);
		    foreach my $prod (keys$datahash->{$data}{'Software'}{
				     'Terms'}{'alpha'}{'word'})
		    {
			$prod = lc($prod);
			$datahash->{$data}{'AuditIDs'}{"$prod$ver"}++;
			foreach my $asset (keys$datahash->{$data}{'Assets'})
			{
			    $sidhash->{"$prod$ver"}{$asset}++;
			}
		    }
		}
	    }
	    elsif (!$datahash->{$data}{'Software'}{'Terms'}{'alpha'}{'word'} &&
		 $datahash->{$data}{'Software'}{'Terms'}{'alpha'}{'alphanum'}||
		 !$datahash->{$data}{'Software'}{'Terms'}{'alpha'}{'number'} &&
		 $datahash->{$data}{'Software'}{'Terms'}{'alpha'}{'alphanum'}
		 )	
	    {
		foreach my $prod (keys$datahash->{$data}{'Software'}{
				 'Terms'}{'alpha'}{'alphanum'})
		{
		    $prod = lc($prod);
		    $datahash->{$data}{'AuditIDs'}{$prod}++;
		    foreach my $asset (keys$datahash->{$data}{'Assets'})
		    {
			$sidhash->{"$prod"}{$asset}++;
		    }
		}
	    }
	}
	elsif ( $datahash->{$data}{'User Agents'} )
	{
	    if ( $datahash->{$data}{'User Agents'}{'Browser Version'} &&
		 $datahash->{$data}{'User Agents'}{'Browser'} )	
	    {
		foreach my $kb (keys$datahash->{
				 $data}{'User Agents'}{'Browser'})
		{
		    foreach my $kbv (keys$datahash->{
				     $data}{'User Agents'}{'Browser Version'})
		    {
			$kb  = lc($kb);
			$kbv = lc($kbv);
			$datahash->{$data}{'AuditIDs'}{"$kb$kbv"}++;
			foreach my $asset (keys$datahash->{$data}{'Assets'})
			{
			    $sidhash->{"$kb$kbv"}{$asset}++;
			}
		    }
		}
	    }
	    if ( $datahash->{$data}{'User Agents'}{'Operating System'} &&
		 $datahash->{$data}{'User Agents'}{'Operating System Version'})	
	    {
		foreach my $os (keys$datahash->{$data}{'User Agents'}{
				'Operating System'})
		{
		    foreach my $osv (keys$datahash->{$data}{'User Agents'}{
				     'Operating System Version'})
		    {
			$os  = lc($os);
			$osv = lc($osv);
			$datahash->{$data}{'AuditIDs'}{"$os$osv"}++;
			foreach my $asset (keys$datahash->{$data}{'Assets'})
			{
			    $sidhash->{"$os$osv"}{$asset}++;
			}
		    }
		}
	    }	    
	}
    }
}
##############################################################################
## Description: Tokenizes a string and fills the tokens structure into a hash
## Syntax     : tokenize($CURRENT_FUNCTION, $STRING, $HASHREF, PARSER, $key)
##############################################################################
sub tokenize
{
    my ($caller, $string, $hash, $parser, $key) = @_;
    my $self = getFunctionName($caller,(caller(0))[3]);
    unless ( $string )
    {
	logMsgT($self,"Empty String to tokenize", 1,$CFG::options{log_file});
	return;
    }
    logMsgT($self,"Parsing tokens from ($string)", 3,$CFG::options{log_file});
    my $decoded_str = uri_decode($string);
    my $tokenizer;
    if ( $key eq 'Software')
    {
	$tokenizer=String::Tokenizer->new($decoded_str,',:/&)(=-~?_+;!%$#][');
    }
    else
    {
	$tokenizer=String::Tokenizer->new($decoded_str,',.:/&)(=-~?_+;!%$#][');
    }
    my @tokens = $tokenizer->getTokens();
    $hash->{$key}{'Full string'}{$string}{$parser}++;
    foreach my $tok (@tokens)
    {
	if ( $tok =~ m/[A-Za-z0-9]/)
	{
	    if    ( $tok =~ m/^[A-Za-z]+$/)
	    {
		$hash->{$key}{Terms}{alpha}{word}{$tok}++;
	    }
	    elsif ( $tok =~ m/^[0-9]+$/)
	    {
		$hash->{$key}{Terms}{alpha}{number}{$tok}++;
	    }
	    else
	    {
		$hash->{$key}{Terms}{alpha}{alphanum}{$tok}++;
	    }
	}
	else
	{
	    $hash->{$key}{Terms}{symbols}{$tok}++;
	}
    }
}
##############################################################################
## Description: Parses User agent and stores fields into a hash
## Syntax     : getPlatforms($CURRENT_FUNCTION, $STRING, $HASHREF, $PARSER)
##############################################################################
sub getPlatforms
{
    my ($caller, $str, $hashrefs, $parser) = @_;
    my $self = getFunctionName($caller,(caller(0))[3]);
    unless ($str)
    {
	logMsgT($self,"Empty OS string", 1, $CFG::options{log_file});
	return;	
    }
    if ( $str =~ m/bsd/i )
    {
	foreach my $outhash (@{$hashrefs})
	{
	    $outhash->{Platforms}{UnixBSD}{$str}{$parser}++;
	}
    }
    elsif ( $str =~ m/linux/i )
    {
	foreach my $outhash (@{$hashrefs})
	{
	    $outhash->{Platforms}{Linux}{$str}{$parser}++;
	}
    }
    elsif ( $str =~ m/windows/i )
    {
	foreach my $outhash (@{$hashrefs})
	{
	    $outhash->{Platforms}{Windows}{$str}{$parser}++;
	}
    }
    elsif ( $str =~ m/(mac|apple|ios|iphone|ipad)/i )
    {
	foreach my $outhash (@{$hashrefs})
	{
	    $outhash->{Platforms}{Apple}{$str}{$parser}++;
	}
    }
    else
    {
	foreach my $outhash (@{$hashrefs})
	{
	    $outhash->{Platforms}{Others}{$str}{$parser}++;
	}
    }
}
##############################################################################
## Description: Parses User agent and stores fields into a hash
## Syntax     : getUserAgentInfo($CURRENT_FUNCTION, $STRING, $HASHREF, $PARSER)
##############################################################################
sub getUserAgentInfo
{
    my ($caller, $ua, $hash, $parser) = @_;
    my $self = getFunctionName($caller,(caller(0))[3]);
    unless ($ua)
    {
	logMsgT($self,"Empty user agent", 1, $CFG::options{log_file});
	return;	
    }
    $hash->{"User Agents"}{"Full ID"}{$ua}{$parser}++;    
    my $uainfo = HTTP::BrowserDetect->new($ua);
    if ( $uainfo->country() )
    {
	$hash->{"User Agents"}{Country}{$uainfo->country()}++;
    }
    if ( $uainfo->language() )
    {
	$hash->{"User Agents"}{Language}{$uainfo->language()}++;
    }
    if ( $uainfo->engine_string() )
    {
	$hash->{"User Agents"}{Engine}{
		$uainfo->engine_string()}++;
    }
    if ($uainfo->browser_string())
    {
	my $browser = $uainfo->browser_string();
	$hash->{"User Agents"}{Browser}{$browser}++;
	if ( $ua =~ m/.*$browser.([^ ;]+).*/ )
	{
	    $hash->{"User Agents"}{"Browser Version"}{$1}++;
	}
	else
	{
	    $hash->{"User Agents"}{"Browser Version"}{'null'}++;
	}
    }
    if ( $uainfo->os_string() )
    {
	my $os = $uainfo->os_string();
	$hash->{"User Agents"}{"Operating System"}{$os}++;
	my $osversion;
	if ( $uainfo->os_string() eq 'Android'  )
	{
	    $ua =~ m/.*$os ([^ ]+);.*/;
	    $hash->{"User Agents"}{"Operating System Version"}{$1}++ if ($1);
	}
	elsif ( $uainfo->os_string() eq 'Windows Phone'  )
	{
	    $ua =~ m/.*$os OS ([^ ]+);.*/;
	    $hash->{"User Agents"}{"Operating System Version"}{$1}++;
	}
	elsif ( $uainfo->os_string() eq 'Mac OS X'  )
	{
	    $ua =~ m/.*$os ([^ ]+)\).*/;
	    if ($1)
	    {
		my $osv = $1;
		$osv =~ s/_/\./g;
		$hash->{"User Agents"}{"Operating System Version"}{$osv}++;
	    }
	}
    }
    if ( $uainfo->windows() )
    {
	if ( $uainfo->os_string() )
	{
	    $hash->{"User Agents"}{Platform}{
		    "Windows"}{$uainfo->os_string()}++;
	}
    }
    elsif ( $uainfo->unix() )
    {
	if ( $uainfo->os_string() )
	{
	    $hash->{"User Agents"}{Platform}{
		    "Unix"}{$uainfo->os_string()}++;
	}
    }
    else
    {
	if ( $uainfo->os_string() )
	{
	    $hash->{"User Agents"}{Platform}{
		    "Other"}{$uainfo->os_string()}++;
	}
    }
    if ( $uainfo->mobile() )
    {	
	if ( $uainfo->device() )
	{
	    $hash->{"User Agents"}{Device}{$uainfo->device()}++;
	}
    }
    elsif ( $uainfo->tablet() )
    {
	if ( $uainfo->device() )
	{
	    $hash->{"User Agents"}{Device}{$uainfo->device()}++;
	}
    }
}
##############################################################################
## Description: Audits Software
## Syntax     : auditSoftware($CURRENT_FUNCTION, $DATAHASH, $DICT)
##############################################################################
sub auditSoftware
{
    my ($caller, $datahash, $outhash, $dict) = @_;
    my $self = getFunctionName($caller,(caller(0))[3]);
    unless ( open(FH_DICT, $dict) )
    {
	logMsgT($self,"Unable to open dictionary file ($dict)",
		0,$CFG::options{log_file});
	return;
    }
    logMsgT($self,"Loading vulnerability dictionary file ($dict)", 
	    2,$CFG::options{log_file});
    my $content = "";                                                           
    open(FH,$dict); 
    while(<FH>)                                                                 
    {                                                                           
	$content .= $_;                                                        
    }                                                                           
    close(FH);
    my @homenet  = split(",",$CFG::options{home_net});
    my $in_homenet = subnet_matcher(@homenet);

    my $nvdhash = decode_json ($content);
    my %cnt;
    $cnt{cve} 		= {};
    $cnt{mprod}		= {};
    $cnt{prod}		= {};
    $cnt{ver}		= {};
    $cnt{match_all}	= {};
    $cnt{match_home}	= {};
    $cnt{asset_all}	= {};
    $cnt{asset_home}	= {};
    foreach my $cve (keys$nvdhash->{CVEs})
    {
	$cnt{cve}{$cve}++;
	foreach my $mprod (keys$nvdhash->{CVEs}{$cve}{'Vulnerable Software'})
	{
	    $cnt{mprod}{$mprod}++;
	    foreach my $prod (keys$nvdhash->{CVEs}{$cve}{
			     'Vulnerable Software'}{$mprod})
	    {
		$cnt{prod}{$prod}++;
		foreach my $ver (keys$nvdhash->{CVEs}{$cve}{
				 'Vulnerable Software'}{$mprod}{$prod})
		{
		    $cnt{ver}{"$prod$ver"}++;
		    next unless ( $ver =~ m/..*/ );
		    if ( $datahash->{"$prod$ver"} )
		    {	
			$cnt{match_all}{"$prod$ver"}++;
			if ( $CFG::options{home_net})
			{
			    foreach my $asset (keys$datahash->{"$prod$ver"})
			    {
				$cnt{asset_all}{$asset}++;
				if ( $in_homenet->($asset) )
				{
				    $cnt{match_home}{"$prod$ver"}++;
				    $cnt{asset_home}{$asset}++;
				    $outhash->{$asset}{CVEs}{$cve}{Product} = 
					"$prod$ver";
				    $outhash->{$asset}{CVEs}{$cve}{Description}=
					$nvdhash->{CVEs}{$cve}{Description};
				    $outhash->{$asset}{CVEs}{$cve}{Score} =
					$nvdhash->{CVEs}{$cve}{Score};
				    $outhash->{$asset}{'Total Score'} += 
					$nvdhash->{CVEs}{$cve}{Score};
			        }
			    }
			}
			else
			{
			    foreach my $asset (keys$datahash->{"$prod$ver"})
			    {
				$cnt{asset_all}{$asset}++;
				$outhash->{$asset}{CVEs}{$cve}{Product} = 
				    "$prod$ver";
				$outhash->{$asset}{CVEs}{$cve}{Description} =
				    $nvdhash->{CVEs}{$cve}{Description};
				$outhash->{$asset}{CVEs}{$cve}{Score} 	=
				    $nvdhash->{CVEs}{$cve}{Score};
				$outhash->{$asset}{'Total Score'} += 
				    $nvdhash->{CVEs}{$cve}{Score};
			    }
			}
		    }
		}
	    }
	    
	}	
    }
    my $cve   = keys$cnt{cve};
    my $mprod = keys$cnt{mprod};
    my $prod  = keys$cnt{prod};
    my $ver   = keys$cnt{ver};
    my $ma    = keys$cnt{match_all};
    my $mh    = keys$cnt{match_home};
    my $aa    = keys$cnt{asset_all};
    my $ah    = keys$cnt{asset_home};
    logMsgT($self," |-- Loaded  ($cve) CVE entries in dictionary",
	    2, $CFG::options{log_file});
    logMsgT($self," |-- Loaded  ($mprod) Main Products in dictionary",
	    2, $CFG::options{log_file});
    logMsgT($self," |-- Loaded  ($prod) Products in dictionary",
	    2, $CFG::options{log_file});
    logMsgT($self," |-- Loaded  ($ver) Versions in dictionary",
	    2, $CFG::options{log_file});
    logMsgT($self," |-- Found    ($ma) vulnerable products in Total",
	    2, $CFG::options{log_file});
    logMsgT($self," |-- Found    ($aa) Assets with vulnerable software",
	    2, $CFG::options{log_file});
    logMsgT($self," |-- Found    ($mh) vulnerable products in HOMENET",
	    2, $CFG::options{log_file});
    logMsgT($self," |-- Found    ($ah) Assets with vulnerable sofware".
	    " in HOMENET", 2, $CFG::options{log_file});
    close(FH_DICT);
}
##############################################################################
## Description: Audits assets based on BlackLists
## Syntax     : auditBlackLists($CURRENT_FUNCTION, $DATAHASH, $OUTHASH, $BL)
##############################################################################
sub auditBlackList
{
    my ($caller, $datahash, $outhash, $bl) = @_;
    my $self = getFunctionName($caller,(caller(0))[3]);
    my %bl;
    my %cat;
    my %cnt;
    $cnt{cat}		= {};
    $cnt{match_all}	= {};
    $cnt{match_home}	= {};
    $cnt{asset_all}	= {};
    $cnt{asset_home}	= {};
    unless ( open(FH_BLCAT, $CFG::options{audit_blcat}) )
    {
	logMsgT($self,"Unable to open Categories file ".
	    "($CFG::options{audit_blcat})", 0, $CFG::options{log_file});
	return;
    }
    logMsgT($self,"Loading Categories file ($CFG::options{audit_blcat})",
	    2, $CFG::options{log_file});
    while(<FH_BLCAT>)
    {
	chomp();
	my @line = split(",",$_);
	$cat{$line[0]}{name} = $line[1];
	$cat{$line[0]}{desc} = $line[2];
    }
    close(FH_BLCAT);
    my @homenet  = split(",",$CFG::options{home_net});
    my $in_homenet = subnet_matcher(@homenet);
    if ( $bl eq "BLI" )
    {
	unless ( open(FH_BLIP, $CFG::options{audit_blip}) )
	{
	    logMsgT($self,"Unable to open $bl BlackList ".
		"($CFG::options{audit_blip})", 0, $CFG::options{log_file});
	    return;
	}
	logMsgT($self,"Loading BlackList (IP) reputation file".
		"($CFG::options{audit_blip})", 2, $CFG::options{log_file});
	while(<FH_BLIP>)
	{
	    chomp();
	    my @line = split(",",$_);
	    $bl{$line[0]}{categories}{$line[1]} = $line[2];
	}
	close(FH_BLIP);
	my $nbl = keys%bl;
	logMsgT($self,"Loaded ($nbl) blacklisted IPs",
		2, $CFG::options{log_file});
	foreach my $track (keys%$datahash)
	{
	    foreach my $proto (keys$datahash->{$track})
	    {
		foreach my $sip (keys$datahash->{$track}{$proto})
		{
		    if ( $CFG::options{home_net} )
		    {
			if ( $bl{$sip} )
			{
			    $cnt{asset_all}{$sip}++;
			    if ( $in_homenet->($sip) )
			    {
				$cnt{asset_home}{$sip}++;
				foreach my $ct (keys$bl{$sip}{categories})
				{
				    my $catname = $ct;
				    if ($cat{$ct}{name})
				    {
					$catname= $cat{$ct}{name} 
				    }
				    $cnt{cat}{$ct}++;
				    $outhash->{$sip}{Categories}{
					$catname}{$sip}{Score} 	=
					$bl{$sip}{categories}{$ct};
				    $outhash->{$sip}{Categories}{
					$catname}{$sip}{Description} 	=
					$cat{$ct}{desc};
				    $outhash->{$sip}{'Total Score'}    +=
					$bl{$sip}{categories}{$ct};
				}			    
			    }
			}
			foreach my $dip (keys$datahash->{$track}{$proto}{$sip})
			{
			    if ( $bl{$dip} )
			    {
				$cnt{asset_all}{$dip}++;
				if ( $in_homenet->($dip) )
				{
				    $cnt{asset_home}{$dip}++;
				    foreach my $ct (keys$bl{$dip}{categories})
				    {
					my $catname = $ct;
					if ($cat{$ct}{name})
					{
					    $catname= $cat{$ct}{name} 
					}

					if ( $in_homenet->($sip) )
					{
					    $cnt{cat}{$ct}++;
					    $outhash->{$sip}{Categories}{
						$catname}{$dip}{Score} 	     =
						$bl{$dip}{categories}{$ct};
					    $outhash->{$sip}{Categories}{
						$catname}{$dip}{Description} =
						$cat{$ct}{desc};
					    $outhash->{$sip}{'Total Score'} +=
						$bl{$dip}{categories}{$ct};
					}
					$cnt{cat}{$ct}++;
					$outhash->{$dip}{Categories}{
					    $catname}{$dip}{Score}       =
					    $bl{$dip}{categories}{$ct};
					$outhash->{$dip}{Categories}{
					    $catname}{$dip}{Description} =
					    $cat{$ct}{desc};
					$outhash->{$dip}{'Total Score'} +=
					    $bl{$dip}{categories}{$ct};
				    }			    
			        }
			    }
			}
		    }
		    else
		    {
			if ( $bl{$sip} )
			{
			    $cnt{asset_all}{$sip}++;
			    foreach my $ct (keys$bl{$sip}{categories})
			    {
				my $catname = $ct;
				if ($cat{$ct}{name})
				{
				    $catname= $cat{$ct}{name} 
				}
				$cnt{cat}{$ct}++;
				$outhash->{$sip}{Categories}{
				    $catname}{$sip}{Score} 	  =
				    $bl{$sip}{categories}{$ct};
				$outhash->{$sip}{Categories}{
				    $catname}{$sip}{Description}  =
				    $cat{$ct}{desc};
				$outhash->{$sip}{'Total Score'}  +=
				    $bl{$sip}{categories}{$ct};
			    }			    
			}
			foreach my $dip (keys$datahash->{$track}{$proto}{$sip})
			{
			    if ( $bl{$dip} )
			    {
				$cnt{asset_all}{$dip}++;
				foreach my $ct (keys$bl{$dip}{categories})
				{
				    my $catname = $ct;
				    if ($cat{$ct}{name})
				    {
					$catname= $cat{$ct}{name} 
				    }
				    $cnt{cat}{$ct}++;
				    $outhash->{$sip}{Categories}{
					$catname}{$dip}{Score}        =
					$bl{$dip}{categories}{$ct};
				    $outhash->{$sip}{Categories}{
					$catname}{$dip}{Description}  =
					$cat{$ct}{desc};
				    $outhash->{$sip}{'Total Score'}  +=
					$bl{$dip}{categories}{$ct};
				}			    
			    }
			}
		    }
		}
	    }
	}
    }
    elsif ( $bl eq "BLD" )
    {
	unless ( open(FH_BLDN, $CFG::options{audit_bldn}) )
	{
	    logMsgT($self,"Unable to open $bl BlackList ".
		"($CFG::options{audit_bldn})", 0, $CFG::options{log_file});
	    return;
	}
	logMsgT($self,"Loading BlackList (DOMAIN) reputation file".
		"($CFG::options{audit_bldn})", 2, $CFG::options{log_file});
	while(<FH_BLDN>)
	{
	    chomp();
	    my @line =  split(",",$_);
	    $line[0] =~ s/ //g;
	    $bl{$line[0]}{categories}{$line[1]} = $line[2];
	}
	close(FH_BLDN);
	my $nbl = keys%bl;
	logMsgT($self,"Loaded ($nbl) blacklisted Domains",
		2, $CFG::options{log_file});
	my @homenet  = split(",",$CFG::options{home_net});
	my $in_homenet = subnet_matcher(@homenet);
	if ( $CFG::options{home_net} )
	{
	    foreach my $domain (keys%$datahash)
	    {
		if ( $bl{$domain} )
		{
		    $cnt{match_all}{$domain}++;
		    foreach my $asset ( keys$datahash->{$domain} )
		    {
			$cnt{asset_all}{$asset}++;
			if ( $in_homenet->($asset) )
			{
			    $cnt{match_home}{$domain}++;
			    $cnt{asset_home}{$asset}++;
			    foreach my $ct (keys$bl{$domain}{categories})
			    {
				my $catname = $ct;
				if ($cat{$ct}{name})
				{
				    $catname= $cat{$ct}{name} 
				}
				$cnt{cat}{$ct}++;
				$outhash->{$asset}{Categories}{
				    $catname}{$domain}{Score} 	    =
				    $bl{$domain}{categories}{$ct};
				$outhash->{$asset}{Categories}{
				    $catname}{$domain}{Description} =
				    $cat{$ct}{desc};
				$outhash->{$asset}{'Total Score'}  +=
				    $bl{$domain}{categories}{$ct};
			    }			    
			}
		    }
		}
	    }
	}
	else
	{
	    foreach my $domain (keys%$datahash)
	    {
		if ( $bl{$domain} )
		{
		    $cnt{match_all}{$domain}++;
		    foreach my $asset ( keys$datahash->{$domain} )
		    {
			$cnt{asset_all}{$asset}++;
			foreach my $ct (keys$bl{$domain}{categories})
			{
			    my $catname = $ct;
			    if ($cat{$ct}{name})
			    {
				$catname= $cat{$ct}{name} 
			    }
			    $cnt{cat}{$ct}++;
			    $outhash->{$asset}{Categories}{$catname}{$domain}{
				'Score'}= $bl{$domain}{categories}{
				$ct};
			    $outhash->{$asset}{Categories}{$catname}{$domain}{
				'Description'}= $cat{$ct}{desc};
			    $outhash->{$asset}{'Total Score'} +=
				$bl{$domain}{categories}{$ct};
			}			    
		    }
		}
	    }
	}
    }
    else
    {
	logMsgT($self,"Unknown blacklist ($bl) ", 0, $CFG::options{log_file});
    }
    my $cat = keys$cnt{cat};
    my $ma  = keys$cnt{match_all};
    my $mh  = keys$cnt{match_home};
    my $aa  = keys$cnt{asset_all};
    my $ah  = keys$cnt{asset_home};

    logMsgT($self," |-- Found ($cat) Blacklist Categories",
	    2, $CFG::options{log_file});
    logMsgT($self," |-- Found ($aa) blacklisted assets",
	    2, $CFG::options{log_file});
    logMsgT($self," |-- Found ($ah) blacklisted assets in HOMENET",
	    2, $CFG::options{log_file});
    logMsgT($self," |-- Found ($ma) blacklisted domains",
	    2, $CFG::options{log_file});
    logMsgT($self," |-- Found ($mh) blacklisted domains in HOMENET",
	    2, $CFG::options{log_file});

}
##############################################################################
##############################################################################
##############################################################################
1;
