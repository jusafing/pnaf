#!/usr/bin/perl -w
#############################################################################
# PASSIVE NETWORK AUDIT FRAMEWORK                                           
# Version 0.1.0                                                            
# By Javier Santillan [2014]                                               
# --------------------------------------------------------------------------
#                                                                            
# File          : PNAF DCM module                                        
# Description   : Standard variables and function for Data Capture Module
#                                                                            
##############################################################################

use strict;
use warnings;

##############################################################################
## Description: Adds a new audit capturing task into the capture pool.
##              It checks whether there is a task that already covers the   
## 		capture window time.
## Syntax     : addFixtimeCapture(CURRENT_FUNCTION, START, STOP)
##############################################################################
sub addFixtimeCapture
{
    my ($function_caller, $start, $stop) = @_;
    my $this_function   = getFunctionName($function_caller,(caller(0))[3]);
    my $capture 	= time . "_fixtime_$start\_$stop";
    my %pool_hash	;
    lockPoolFile($this_function, "capture", $capture);
    readPoolFile($this_function, "$CFG::log_dir/pool.capture", \%pool_hash); 
    
    
}
##############################################################################
## Description: Adds a new 'fixsize' audit capturing task into the capture pool
## Syntax     : addFixsizeCapture(CURRENT_FUNCTION, SIZE)
##############################################################################
sub addFixsizeCapture
{
    my ($function_caller, $size) = @_;
    my $this_function  	= getFunctionName($function_caller,(caller(0))[3]);
    my $capture 	= time . "_fixsize_$size";
    my %pool_hash	;
    lockPoolFile($this_function, "capture", $capture);
    readPoolFile($this_function,
		 "$CFG::options{log_dir}/pool.capture", \%pool_hash);
    if ( $pool_hash{$capture} )
    {
	logMsgT($this_function,
	       "Capture ($capture) already exists", 1,$CFG::options{log_file});
    }
    else
    {
	logMsgT($this_function,
	       "Adding capture ($capture) to pool", 2,$CFG::options{log_file});
	$pool_hash{$capture} = 1;
	writePoolFile($this_function,
		 "$CFG::options{log_dir}/pool.capture", \%pool_hash);
    }
    print "VAL: $GV::pool_lock{capture}\n";
    unlockPoolFile($this_function, "capture", $capture);
}

##############################################################################
## Description: Adds a new 'fixcount' audit capture task into the capture pool
## Syntax     : addFixcountCapture(CURRENT_FUNCTION, COUNT)
##############################################################################
sub addFixcountCapture
{
    my ($function_caller, $count) = @_;
    my $this_function  = getFunctionName($function_caller,(caller(0))[3]);
    my $capture = time . "_fixcount_$count";
    lockPoolFile($this_function, "capture", $capture);    
}

##############################################################################
## Description: Reads standard PNAf pool file. It receives the file to read 
##		Such files should have the following pnaf format
##		Full    :	epoch_full
##		Fixtime :	epoch_fixtime_start_stop
##		Fixsize :	epoch_fixsize_size
##		Fixcount:	epoch_fixtime_count
##		It stores the content into the hash passed as argument
## Syntax     : readPoolFile(CURRENT_FUNCTION, FILE, OUTHASH_REF)
##		** Note: It uses a hash to use further validation features
##############################################################################
sub readPoolFile
{
    my ($function_caller, $file, $out_hash_ref) = @_;
    my $this_function  = getFunctionName($function_caller,(caller(0))[3]);
    if ( open(FH, "<$file") )
    {
	logMsgT($this_function,
	       "Reading pool records of ($file)", 3, $CFG::options{log_file});
	while ( <FH> )
	{
#	    next if $_ !~ m/[a-z0-9]+\|[[a-z0-9]+\|]*/ ;
	    chomp();
	    $out_hash_ref->{$_} = 1 ;
	    logMsgT($this_function,
		    "Record found ($_)", 3, $CFG::options{log_file});
	}
	close(FH);
    }
    else
    {
        logMsgT($this_function,
		"Unable to read file ($file)", 0, $CFG::options{log_file});
    }
}

##############################################################################
## Description: Writes standard PNAf pool file. It receives the file to write 
##		It will write the file with the following format:
##		Full    :	epoch_full
##		Fixtime :	epoch_fixtime_start_stop
##		Fixsize :	epoch_fixsize_size
##		Fixcount:	epoch_fixtime_count
##		It taken data from hash passed as argument to store it on file
## Syntax     : readPoolFile(CURRENT_FUNCTION, FILE, OUTHASH_REF)
##		** Note: It uses a hash to use further validation features
##############################################################################
sub writePoolFile
{
    my ($function_caller, $file, $hash_ref) = @_;
    my $this_function  = getFunctionName($function_caller,(caller(0))[3]);
    if ( open(FH, ">$file") )
    {
	logMsgT($this_function,
	       "Writting pool records on ($file)", 3, $CFG::options{log_file});
	foreach my $cap ( keys%$hash_ref )
	{
	    print FH "$cap\n";
	    logMsgT($this_function,
		    "New pool record ($cap)", 3, $CFG::options{log_file});
	}
	close(FH);
    }
    else
    {
        logMsgT($this_function,
		"Unable to write on file ($file)", 0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Locks the pool flag to avoid parallel changes
## Syntax     : lockPoolFile(CURRENT_FUNCTION, TYPE, REASON)
##############################################################################
sub lockPoolFile
{
    my ($function_caller, $type, $reason) = @_;
    my $this_function   = getFunctionName($function_caller,(caller(0))[3]);
    my $dir 		= $CFG::options{log_dir};
    if ( $GV::pool_lock{$type} )
    {
        logMsgT($this_function,
		"Lock status of ($type) : ($GV::pool_lock{$type})",
		3, $CFG::options{log_file});
	if ( $GV::pool_lock{$type} eq "none" )
	{
            logMsgT($this_function,
		    "Locking file ($dir/pool.$type) to add:($reason)",
		    3, $CFG::options{log_file});
	    $GV::pool_lock{$type} = $reason;
	    return 1;
	}
	else
	{
	    logMsgT($this_function,
		    "File already locked by ($GV::pool_lock{$type}",
		    1, $CFG::options{log_file});
	    return 0;
	}
    }
    else
    {
        logMsgT($this_function,
		"Invalid lock type ($type)", 0, $CFG::options{log_file});
	return -1;
    }
}
##############################################################################
## Description: Unlocks the pool flag
## Syntax     : unLockPoolFile(CURRENT_FUNCTION, TYPE, REASON)
##############################################################################
sub unlockPoolFile
{
    my ($function_caller, $type, $locker) = @_;
    my $this_function   = getFunctionName($function_caller,(caller(0))[3]);
    my $dir 		= $CFG::options{log_dir};
    if ( $GV::pool_lock{$type} eq $locker )
    {
        logMsgT($this_function,
		"Unlocking pool file ($type) by ($locker)", 
		3, $CFG::options{log_file});
	$GV::pool_lock{$type} = "none";
    }
    else
    {
        logMsgT($this_function,
		"Unable to unlock. Locker mismatch ($type)", 
		0, $CFG::options{log_file});
	return -1;
    }
}

##############################################################################
##############################################################################
1;
