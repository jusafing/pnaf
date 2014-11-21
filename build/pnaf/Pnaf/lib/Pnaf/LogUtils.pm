use strict;
use warnings;
use Pnaf::Core;
use POSIX;
##############################################################################
##    Log Utils 0.2.0                                                        #
##############################################################################
##    Copyright (C) <2012>  <Javier Santillan>                               #
##                                                                           #
##    This program is free software: you can redistribute it and/or modify   #
##    it under the terms of the GNU General Public License as published by   #
##    the Free Software Foundation, either version 3 of the License, or      #
##    (at your option) any later version.                                    #
##                                                                           #
##    This program is distributed in the hope that it will be useful,        #
##    but WITHOUT ANY WARRANTY; without even the implied warranty of         #
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          #
##    GNU General Public License for more details.                           #
##                                                                           #
##    You should have received a copy of the GNU General Public License      #
##    along with this program.  If not, see <http://www.gnu.org/licenses/>.  #
##############################################################################
package main;
##############################################################################
##############################################################################
## Description: Log message function with tracking support		    ##
## Author     : Javier Santillan					    ##
## Syntax     : logMsgT(FUNCTION_NAME,MESSAGE,CODE,LOG_FILE)	  	    ##
## Options    : CODE  >  -1>FATAL_ERROR 0>ERROR  1>WARNING  2>INFO  3>DEBUG ##
## 
## IMPORTANT  : Replace $CFG::options{XXX} with your corresponding control
##		variable to set the control of DEBUG, VERBOSE and QUIET
##		options. 
##############################################################################
sub logMsgT
{
    my ($function_name, $msg_data, $msg_code, $logfile, $quiet) = @_;
    return if ($msg_code == 3 && $CFG::options{debug} !~ m/(yes)|1/);
    my $msg_prefix	  ;
    my $logfile_fh	  ;
    my $function 	  = '';
    my $msg_timestamp = getTimestamp("localtime", "Tdate");
    
    if    ( $msg_code   == -1 )	{$msg_prefix = "FATAL"	;}
    elsif ( $msg_code   ==  0 )	{$msg_prefix = "ERROR"	;}
    elsif ( $msg_code   ==  1 )	{$msg_prefix = "WARNING";}
    elsif ( $msg_code   ==  2 )	{$msg_prefix = "INFO"	;}
    elsif ( $msg_code   ==  3 )	{$msg_prefix = "DEBUG"	;}
    else		 	{$msg_prefix = "UNDEFINED";}

    if ( $CFG::options{debug} )
    {
	if ( $CFG::options{debug} =~ m/(yes)|1/ )
	{
	    $function    = "[$function_name]";
	    my $pid      = getpid();
	    $msg_prefix  = "($pid) $msg_prefix";
	    $msg_data = sprintf("[%-.20s] %-15s %.80s - %s\n",
			        $msg_timestamp, $msg_prefix,
				$function,$msg_data);
	}
	else
	{
	    if ( $msg_code == 0 )
	    {
		$msg_data = sprintf("[%-.20s] %-7s - %s -> Reference(%s)\n",
			    $msg_timestamp, $msg_prefix, $msg_data,
			    $function_name);
	    }
	    else
	    {
		$msg_data = sprintf("[%-.20s] %-7s - %s\n",
				$msg_timestamp, $msg_prefix, $msg_data);
	    }
	}
    }
    else
    {
        die "FATAL, No debug option defined\n"
    }
    unless (open($logfile_fh,">>$logfile"))
    {
        die "FATAL, Unable to write on log file ($logfile)";
    }
    if ( $msg_code ==-1 )
    {
	print $logfile_fh "$msg_data";
	die "$msg_data\n";
    }
    else
    {
	print $logfile_fh "$msg_data";
	print "$msg_data" unless (defined $quiet);
	close($logfile_fh);
    }
}
##############################################################################
##############################################################################
## Description: Returns function_caller + function_name	for tracking        ##
## Author     : Javier Santillan					    ##
## Syntax     : getFunctionName(CURRENT_FUNCTION_CALLER,FUNCTION_NAME)	    ##
##############################################################################
sub getFunctionName
{
    my ($current_function_caller,$function_name) = @_;
    my @names = split(/::/,$function_name);
    return "$current_function_caller|$names[1]";
}
##############################################################################
##############################################################################
## Description: Gets the timestamp of current time			    ##
## Author     : Javier Santillan					    ##
## Syntax     : getTimestamp(TIME_ZONE,TYPE_REQUEST)	 		    ##
## Options    : TIME_ZONE    >  localtime, utc				    ##
## Options    : TYPE_REQUEST >  TDate, Ddate, Hdate			    ##
##############################################################################
sub getTimestamp
{
    my ($time_zone, $time_request) = @_;
    my ($sec, $min, $hour, $day, $mon, $year, $wday, $yday, $isdst);
    if ( $time_zone eq "localtime" )
    {
	    ($sec, $min, $hour, $day, $mon, $year,
	     $wday, $yday, $isdst)=localtime(time);
    }
    elsif ($time_zone eq "utc")
    {
	    ($sec, $min, $hour, $day, $mon, $year,
	     $wday, $yday, $isdst)=gmtime(time);
    }
    else
    {
	    ($sec, $min, $hour, $day, $mon, $year, 
	     $wday, $yday, $isdst)=localtime(time);
    }
    my $Tdate = sprintf("%4d-%02d-%02dT%02d:%02d:%02d",
		$year+1900,$mon+1,$day-1,$hour,$min,$sec);
    my $Ddate = sprintf("%4d%02d%02d",$year+1900,$mon+1,$day);
    my $Hdate = sprintf("%02d%02d",$hour,$min);
    return $Tdate if ($time_request eq "Tdate");
    return $Ddate if ($time_request eq "Ddate");
    return $Hdate if ($time_request eq "Hdate");
}

##############################################################################
##############################################################################
1;
