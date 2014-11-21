#!/usr/bin/perl -w                                                              
##############################################################################  
# PASSIVE NETWORK AUDIT FRAMEWORK                                               
# Version 0.1.0                                                                 
# By Javier Santillan [2014]                                                    
# ----------------------------------------------------------------------------  
#                                                                               
# File          : PNAF Core module
# Description   : Standard variables and functions.       
#                                                                               
##############################################################################  
use strict;      
use warnings;
use Pnaf::LogUtils;
use Getopt::Long;
use Config::Auto;
use Pod::Usage;
use YAML;
use Proc::Daemon;
use POSIX;
use JSON::XS;
use SnortUnified(qw(:ALL));
use Digest::MD5 qw(md5 md5_base64);
use MIME::Base64; 
use Devel::Hexdump 'xd';
#use NetAddr::IP::Util qw(inet_ntoa);

##############################################################################  
package CFG;
    # General
    our %versions = (
	    pnaf	=> "0.1.0"			,
	    argus	=> "3.0.6"			,
	    barnyard	=> "2"				,
	    bro		=> "2.3"			,
	    chaosreader	=> "2"				,
	    cxtracker	=> "github_52318e60d5"		,
	    daq		=> "2.0.2"			,
	    dnsdump	=> "1.11"			,
	    httpry	=> "github_7dc427196a"		,
	    ldns	=> "1.6.17"			,
	    libdnet	=> "1.11"			,
	    libfixbuf	=> "1.4.0"			,
	    libpcap	=> "1.6.2"			,
	    luajit	=> "2.0.2"			,
	    mysqlib	=> "6.1.3-linux-glibc2.5-x86_64",
	    nftracker	=> "github_c9a920c324"		,
	    p0f		=> "3.06b"			,
	    prads	=> "github_3c751c869e"		,
	    passivedns	=> "github_fe8f48a3c0"		,
	    ra		=> "3.0.6"			,
	    silk	=> "3.8.1"			,
	    snort_odp	=> "2014-05-30.205-0"		,
	    snort	=> "2.9.7.0"			,
	    ssldump	=> "0.9b3"			,
	    suricata	=> "2.0.3"			,
	    tcpdstat	=> "github_be5bd28da"		,
	    tcpdump	=> "4.5.1"			,
	    tcpflow	=> "1.3/1.4.4"			,
	    tcpxtract	=> "1.0.1"			,
	    vrt_rules	=> "2960"			,
	    xplico	=> "1.1.0"			,
	    yaf		=> "2.5.0"			,
	    yafmediator	=> "1.4.1"			,
	    mkdir	=> "(OS version)"		,
		    );
    # Valid parsers
    our %parsers = (
	    argusFlow	=> "on"				,
	    p0f		=> "on"				,
	    prads	=> "on"				,
	    snortAppId	=> "on"				,
	    suricataHttp=> "off"			,
	    httpry	=> "on"				,
	    tcpdstat	=> "on"				,
	    tcpflow	=> "on"				,
	    suricataEve	=> "on"				,
	    snortIds	=> "on"				,
	    bro		=> "on"				,
	    );
    # Argument Hash
    our %args		  ;
    # Files Hash
    our %files		  ;
    # Configuration options
    our %options	  ;
    # Default basic options
    $options{daemon} 	  	 = "no"					;
    $options{debug} 	  	 = "no"					;
    $options{payload} 	  	 = "no"					;
    $options{path} 	  	 = "/pnaf"				;
    $options{mode}	  	 = "full"				;
    $options{home_net}	  	 = ""					;
    $options{dpm_ids_engine}  	 = "suricata"				;
    $options{dpm_ids_depth}  	 = "high"				;
    $options{dpm_nfa_depth}  	 = "high"				;
    $options{tf_suricata}	 = "%Y-%m-%d %H:%M:%S"			;
    $options{tf_snort}	   	 = "%m/%d/%Y-%H:%M:%S"			;
    $options{tf_p0f}	   	 = "%Y/%m/%d %H:%M:%S"			;
    $options{tf_httpry}	   	 = "%Y/%m/%d %H:%M:%S"			;
    $options{tf_prads}	   	 = "epoch"				;
    $options{lfs_suricataHttp}	 = '\|' 				;
    $options{lf_suricataHttp} 	 = "ts|hpx|hua|pt|hmt|dm|rs|hsc|hrb|"	.
				   "si|sp|di|dp"			;
    $options{lfs_httpry}   	 = '\t' 				;
    $options{lf_httpry}   	 = "ts|sip|dip|dr|hmt|dm|rs|pt|hsc|hrp"	;
    $options{lfs_prads}   	 = ',' 					;
    $options{lf_prads}   	 = "pas|pvl|ppr|ppt|psv|psi|pds|ts"	;
    $options{out_dataset}   	 = "all,audit"				;
    #Default options for Bro parser
    $options{parser_bro_conn}	 = "id.orig_h,id.orig_p,id.resp_h,id.resp_p," .
				   "proto,service,conn_state,tunnel_parents," ;
    $options{parser_bro_weird}	 = "id.orig_h,id.orig_p,id.resp_h,id.resp_p," .
				   "name,peer"				      ;
    $options{parser_bro_dns}	 = "id.orig_h,id.orig_p,id.resp_h,id.resp_p," .
				   "rcode_name,TTLs,AA,RA,proto,rejected,"    .
				   "query,qtype_name,rcode,qtype,qclass,"     .
				   "qclass_name,Z"			      ;
    $options{parser_bro_ssh}	 = "id.orig_h,id.orig_p,id.resp_h,id.resp_p," .
				   "status,direction,client,server"	      ;
    $options{parser_bro_http}	 = "id.orig_h,id.orig_p,id.resp_h,id.resp_p," .
				   "info_code,referrer,resp_mime_types,"      .
				   "password,method,status_msg,proxied,"      .
				   "info_msg,status_code,user_agent,username,".
				   "tags,host,uri,filename,orig_mime_types"   ;
    $options{parser_bro_files}	 = "source,sha1,seen_bytes,analyzers,sha256," .
				   "mime_type,extracted,filename,md5"	      ;
    $options{parser_bro_snmp}	 = "id.orig_h,id.orig_p,id.resp_h,id.resp_p," .
				   "get_bulk_requests,display_string,version,".
				   "set_requests,get_requests,community,"     .
				   "get_responses"			      ;
    $options{parser_bro_ssl}	 = "id.orig_h,id.orig_p,id.resp_h,id.resp_p," .
				   "cert_chain_fuids,client_issuer,issuer,"   .
				   "cipher,curve,version,subject,"            .
				   "client_subject,server_name"		      ;
    $options{parser_bro_tunnel}  = "id.orig_h,id.orig_p,id.resp_h,id.resp_p," .
				   "tunnel_type,action"			      ;
    $options{parser_bro_x509}	 = "certificate.key_type,certificate.sig_alg,".
				   "certificate.subject,certificate.curve,"   .
				   "san.email,certificate.issuer,san.uri,"    .
				   "certificate.key_alg,basic_constraints.ca,".
				   "san.dns,san.ip,certificate.exponent,"     .
				   "certificate.serial,certificate.version,"  .
				   "certificate.key_length,"		      .
				   "certificate.not_valid_before,"	      .
				   "certificate.not_valid_after"	      ;
	
package GV;
    our %pool_lock = (
		    capture => 'none',
		    audit   => 'none',
		     );
    our %daemons   = (
		    capture => 1,
		    audit   => 1,
		     );
    our $pid_max_file	    =  "/proc/sys/kernel/pid_max";
    our $instance_logdir    ;
package main; 

##############################################################################
## Description: Shows current execution configuration variables		    ##
## Syntax     : showCfg(CURRENT_FUNCTION)			  	    ##
##############################################################################  
sub defineVarsWithPath
{
    $CFG::options{config_file} 	  = "$CFG::options{path}/etc/pnaf.conf"	 ;
    $CFG::options{audit_dict} 	  = "$CFG::options{path}/etc/pnaf_dict.json";
    $CFG::options{audit_blip} 	  = "$CFG::options{path}/etc/pnaf_blip.dat";
    $CFG::options{audit_bldn} 	  = "$CFG::options{path}/etc/pnaf_bldn.dat";
    $CFG::options{audit_blcat} 	  = "$CFG::options{path}/etc/pnaf_blcat.dat";
    $CFG::options{dcm_path} 	  = "$CFG::options{path}/dcm"		 ;
    $CFG::options{dpm_path} 	  = "$CFG::options{path}/dpm"		 ;
    $CFG::options{dvm_path} 	  = "$CFG::options{path}/dvm"		 ;
    $CFG::options{dpm_npee_path}  = "$CFG::options{path}/dpm/npee"	 ;
    $CFG::options{dpm_idse_path}  = "$CFG::options{path}/dpm/idse"	 ;
    $CFG::options{dpm_nfae_path}  = "$CFG::options{path}/dpm/nfae"	 ;
    $CFG::options{dpm_dpie_path}  = "$CFG::options{path}/dpm/dpie"	 ;
    $CFG::options{log_dir}	  = "$CFG::options{path}/log/"		 ;
    $CFG::options{log_file}	  = "$CFG::options{path}/log/pnaf.log"	 ;
    $CFG::options{pid_file}	  = "$CFG::options{path}/log/pnaf.pid"	 ;
    $CFG::options{dvm_report_dir} = "$CFG::options{path}/reports"	 ;
    $CFG::options{dvm_web_dir}    = "$CFG::options{path}/www/"		 ;
    $CFG::files{argus}	          = "$CFG::options{path}/bin/argus"	 ;
    $CFG::files{barnyard}         = "$CFG::options{path}/bin/barnyard"	 ;
    $CFG::files{bro}	          = "$CFG::options{path}/bin/bro"	 ; 
    $CFG::files{chaosreader}      = "$CFG::options{path}/bin/chaosreader";
    $CFG::files{cxtracker}        = "$CFG::options{path}/bin/cxtracker"	 ;
    $CFG::files{dnsdump}          = "$CFG::options{path}/bin/dnsdump"	 ;
    $CFG::files{httpry}	          = "$CFG::options{path}/bin/httpry"	 ;
    $CFG::files{nftracker}        = "$CFG::options{path}/bin/nftracker"	 ;
    $CFG::files{p0f}	          = "$CFG::options{path}/bin/p0f"	 ;
    $CFG::files{p0f_fp}	          = "$CFG::options{path}/etc/p0f.fp"	 ;
    $CFG::files{prads}	          = "$CFG::options{path}/bin/prads"	 ;
    $CFG::files{prads_conf}       = "$CFG::options{path}/etc/prads.conf" ;
    $CFG::files{passivedns}       = "$CFG::options{path}/bin/passivedns" ;
    $CFG::files{ra}	          = "$CFG::options{path}/bin/ra"	 ;
    $CFG::files{silk}	          = "$CFG::options{path}/bin/silk"	 ;
    $CFG::files{snort}		  = "$CFG::options{path}/bin/snort"	 ;
    $CFG::files{snort_conf}	  = "$CFG::options{path}/etc/snort.conf" ;
    $CFG::files{snortAppId}       = "$CFG::options{path}/bin/u2openappid";
    $CFG::files{ssldump}          = "$CFG::options{path}/bin/ssldump"	 ;
    $CFG::files{suricata}         = "$CFG::options{path}/bin/suricata"	 ;
    $CFG::files{suricata_conf}    = "$CFG::options{path}/etc/suricata.yaml";
    $CFG::files{tcpdstat}         = "$CFG::options{path}/bin/tcpdstat"	 ;
    $CFG::files{tcpdump}          = "$CFG::options{path}/bin/tcpdump"	 ;
    $CFG::files{tcpflow}          = "$CFG::options{path}/bin/tcpflow"	 ;
    $CFG::files{tcpxtract}        = "$CFG::options{path}/bin/tcpxtract"	 ;
    $CFG::files{tcpxtract_conf}   = "$CFG::options{path}/bin/tcpxtract"	 ;
    $CFG::files{xplico}	          = "$CFG::options{path}/bin/xplico"	 ;
    $CFG::files{yaf}	          = "$CFG::options{path}/bin/yaf"	 ;
    $CFG::files{yafmediator}      = "$CFG::options{path}/bin/" .
				    "yaf_silk_mysql_mediator"		 ;
}
##############################################################################
## Description: Shows current execution configuration variables		    ##
## Syntax     : showCfg(CURRENT_FUNCTION)			  	    ##
##############################################################################  
sub showCfg
{
    my ($function_caller, $set) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    if ( $set eq "debug" )
    {
        foreach my $cfgvar (sort keys %CFG::options)
	{
	    if ( $CFG::options{$cfgvar} )
	    {
		logMsgT ($self, "$cfgvar : $CFG::options{$cfgvar}", 3,
			 $CFG::options{log_file} ) ;
	    }
	}
        foreach my $file (sort keys %CFG::files)
	{
	    if ( $CFG::files{$file} )
	    {
		logMsgT ($self, "$file : $CFG::files{$file}", 3,
			 $CFG::options{log_file} ) ;
	    }
	}
    }
    elsif ( $set eq "summary" )
    {
	logMsgT($self, "Debug           : $CFG::options{debug}",
	        2, $CFG::options{log_file});
	logMsgT($self, "Cfg file        : $CFG::options{config_file}",
		2, $CFG::options{log_file});
	logMsgT($self, "Log file        : $CFG::options{log_file}",
		2, $CFG::options{log_file});
	logMsgT($self, "Log directory   : $CFG::options{log_dir}",
		2, $CFG::options{log_file});
	logMsgT($self, "Report directory: $CFG::options{dvm_report_dir}",
		2, $CFG::options{log_file});
	logMsgT($self, "Exec mode       : $CFG::options{mode}",
		2, $CFG::options{log_file});
	if ( $CFG::options{cap_file} )
	{
	    logMsgT($self, "Capture File    : $CFG::options{cap_file}",
		    2, $CFG::options{log_file});
	}
	if ( $CFG::options{mode} eq "fixtime" )
	{
	    logMsgT($self,"Fixtime Start   : $CFG::options{mode_fixtime_start}",
		    2, $CFG::options{log_file});
	    logMsgT($self,"Fixtime Stop    : $CFG::options{mode_fixtime_stop}",
		    2, $CFG::options{log_file});
	}
	if ( $CFG::options{mode} eq "fixcount" )
	{
	    logMsgT($self, "Fixcount (pkts) : $CFG::options{mode_fixcount}",
		    2, $CFG::options{log_file});
	}
	if ( $CFG::options{mode} eq "fixsize" )
	{
	    logMsgT($self, "Fixsize (Mb)    : $CFG::options{mode_fixsize}",
		    2, $CFG::options{log_file});
	}
	logMsgT($self, "DPM             : $CFG::options{dpm_ids_engine}",
		2, $CFG::options{log_file});
	logMsgT($self, "IDS depth       : $CFG::options{dpm_ids_depth}",
		2, $CFG::options{log_file});
	logMsgT($self, "NFA depth       : $CFG::options{dpm_nfa_depth}",
		2, $CFG::options{log_file});
	logMsgT($self, "DPI depth       : $CFG::options{dpm_dpi_depth}",
		2, $CFG::options{log_file});
    }
    else
    {
	logMsgT ($self, "Invalid set to show (config vars)",
		 2, $CFG::options{log_file} );	
    }
}

##############################################################################
## Description: Reads the configuration file				    ##
## Syntax     : readConfigFile(CURRENT_FUNCTION)			    ##
##############################################################################  
sub readConfigFile
{
    my ($function_caller, $config_file) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    logMsgT ($self, "Loading configuration file ($config_file)",
	     2, $CFG::options{log_file} );
    my $config=Config::Auto::parse("$CFG::options{config_file}",format=>"yaml");
    my %cfgvars_execution = %{ $config->{execution} || {} };
    my %cfgvars_logging   = %{ $config->{logging}   || {} };
    my %cfgvars_mod_dcm   = %{ $config->{mod_dcm}   || {} };
    my %cfgvars_mod_dpm   = %{ $config->{mod_dpm}   || {} };
    my %cfgvars_mod_dvm   = %{ $config->{mod_dvm}   || {} };
    foreach my $cfgvar (keys %cfgvars_execution)
    {
	$cfgvars_execution{$cfgvar} =~ s/#.*//;
	$CFG::options{$cfgvar} = $cfgvars_execution{$cfgvar};
    }
    foreach my $cfgvar (keys %cfgvars_logging)
    {
	$cfgvars_logging{$cfgvar} =~ s/#.*//;
	$CFG::options{$cfgvar} = $cfgvars_logging{$cfgvar};
    }
    foreach my $cfgvar (keys %cfgvars_mod_dcm)
    {
	$cfgvars_mod_dcm{$cfgvar} =~ s/#.*//;
	$CFG::options{$cfgvar} = $cfgvars_mod_dcm{$cfgvar};
    }
    foreach my $cfgvar (keys %cfgvars_mod_dpm)
    {
	$cfgvars_mod_dpm{$cfgvar} =~ s/#.*//;
	$CFG::options{$cfgvar} = $cfgvars_mod_dpm{$cfgvar};
    }
    foreach my $cfgvar (keys %cfgvars_mod_dvm)
    {
	$cfgvars_mod_dvm{$cfgvar} =~ s/#.*//;
	$CFG::options{$cfgvar} = $cfgvars_mod_dvm{$cfgvar};
    }
}

##############################################################################
## Description: Prints PNAF banner					    ##
## Syntax     : printBanner(CURRENT_FUNCTION)				    ##
##############################################################################  
sub printBanner
{
    print "\n";
    print "=======================================\n";
    print " Passive Network Audit Framework (PNAF)\n";
    print " Version $CFG::versions{pnaf}          \n";
    print "=======================================\n\n";
}

##############################################################################
## Description: Reads arguments from @ARGV 				    ##
## Syntax     : readArguments(CURRENT_FUNCTION)				    ##
##############################################################################
sub readArguments
{
    my ($function_caller) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    GetOptions(
	"cap_file=s"   	 	 => \$CFG::args{"cap_file"},
	"conf=s"  	     	 => \$CFG::args{"config_file"},
        "debug"    		 => \$CFG::args{"debug"},
        "daemon"    		 => \$CFG::args{"daemon"},
        "help"    		 => \$CFG::args{"help"},
	"mode=s"   	 	 => \$CFG::args{"mode"},
	"path=s"   	 	 => \$CFG::args{"path"},
	"parser=s"   	 	 => \$CFG::args{"parser"},
	"out_dataset=s"   	 => \$CFG::args{"out_dataset"},
	"home_net=s"   	 	 => \$CFG::args{"home_net"},
	"audit_dict=s" 	 	 => \$CFG::args{"audit_dict"},
	"mode_fixtime_start=s" 	 => \$CFG::args{"mode_fixtime_start"},
	"mode_fixtime_stop=s"  	 => \$CFG::args{"mode_fixtime_stop"},
	"mode_fixcount=i" 	 => \$CFG::args{"mode_fixcount"},
	"mode_fixsize=i"   	 => \$CFG::args{"mode_fixsize"},
	"verbose"		 => \$CFG::args{verbose},
	"log_dir=s"		 => \$CFG::args{log_dir},
	"instance_dir=s"	 => \$CFG::args{instance_dir},
	"log_file=s"		 => \$CFG::args{log_file},
	"pid_file=s"		 => \$CFG::args{pid_file},
	"payload"		 => \$CFG::args{payload},
	"dcm_capture=s"	     	 => \$CFG::args{dcm_capture},
	"dcm_stime=s"	     	 => \$CFG::args{dcm_stime},
    	"dcm_etime=s"	     	 => \$CFG::args{dcm_etime},
        "dpm_ids_engine=s"	 => \$CFG::args{dpm_ids_engine},
        "dpm_ids_depth=s"	 => \$CFG::args{dpm_ids_depth},
	"dpm_ids_rule_path=s"    => \$CFG::args{dpm_ids_rule_path},
        "dpm_ids_rule_updater=s" => \$CFG::args{dpm_ids_rule_updater},
	"dpm_nfa_depth=s"        => \$CFG::args{dpm_nfa_depth},
	"dpm_dpi_depth=s"        => \$CFG::args{dpm_dpi_depth},
        "dpm_dpi_http"	         => \$CFG::args{dpm_dpi_http},
	"dpm_dpi_dns"	         => \$CFG::args{dpm_dpi_dns},
	"dpm_dpi_smtp"	         => \$CFG::args{dpm_dpi_smtp},
	"dpm_dpi_ssltls"         => \$CFG::args{dpm_dpi_ssltls},
	"dpm_dpi_blacklist"      => \$CFG::args{dpm_dpi_blacklist},
	"dpm_dpi_malware"        => \$CFG::args{dpm_dpi_malware},
	"dpm_dpi_files"	         => \$CFG::args{dpm_dpi_files},
	"dpm_nsa_depth=s"        => \$CFG::args{dpm_nsa_depth},
	"dpm_nsa_policies=s"     => \$CFG::args{dpm_nsa_policies},
	"dvm_graphic"	         => \$CFG::args{dvm_graphic},
	"dvm_report_general=s"   => \$CFG::args{dvm_report_general},
	"dvm_report_npe=s"       => \$CFG::args{dvm_report_npe},
	"dvm_report_ids=s"       => \$CFG::args{dvm_report_ids},
	"dvm_report_nfa=s"       => \$CFG::args{dvm_report_nfa},
	"dvm_report_dpi=s"       => \$CFG::args{dvm_report_dpi},
	"dvm_report_nsa=s"       => \$CFG::args{dvm_report_nsa},
	"version"  		 => \$CFG::args{"version"})
	or pod2usage(2);
	pod2usage(1) if $CFG::args{help}	;
	showVersions($self,"normal") if $CFG::args{version};
    # Overwriting basic options (for logging and show information)
    if ( $CFG::args{"config_file"} )
    {
	$CFG::options{"config_file"} = $CFG::args{"config_file"};
    }
    if ( $CFG::args{log_file} )
    {
	$CFG::options{log_file}	 = $CFG::args{log_file};
    }
    if ( $CFG::args{"debug"} )
    {
	$CFG::options{"debug"} 	 = $CFG::args{"debug"};
    }
}

##############################################################################
## Description: Reads arguments from @ARGV 				    ##
## Syntax     : readArguments(CURRENT_FUNCTION, MODE)			    ##
##############################################################################
sub loadConfig
{
    my ($function_caller, $mode) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    
    # Define default options
    defineVarsWithPath();
    if ( $mode eq "auditor" )
    {
	$CFG::options{config_file} = "$CFG::options{path}/etc/auditor.conf";
    }
    # Reading arguments
    readArguments($self);
    if ( -e $CFG::options{"config_file"} )
    {
	readConfigFile($self, $CFG::options{"config_file"});
    }
    else
    {
	logMsgT ($self,
		 "Unable to read config file ($CFG::options{config_file})",
                 0, $CFG::options{log_file});
	logMsgT ($self,
		 "Create file ($CFG::options{config_file} or set '--conf'",
                 0, $CFG::options{log_file});
	print "\n";
	pod2usage(1);
    }
    # Updating options
    updateOptions($self);
}
##############################################################################
## Description: Updates configuration options from arguments                ##
## Syntax     : updateOptions(CURRENT_FUNCTION)				    ##
##############################################################################
sub updateOptions
{
    my ($function_caller) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    # Overwriting basic options (for logging and show information)
    if ( $CFG::args{"config_file"} )
    {
	$CFG::options{"config_file"} = $CFG::args{"config_file"};
    }
    if ( $CFG::args{log_file} )
    {
	$CFG::options{log_file}	 = $CFG::args{log_file};
    }
    if ( $CFG::args{"debug"} )
    {
	$CFG::options{"debug"} 	 = $CFG::args{"debug"};
    }
    if ( $CFG::args{"path"} )
    {
	$CFG::options{"path"} 	= $CFG::args{"path"};
	defineVarsWithPath();
    }
    # Updating specific given arguments
    foreach my $cfg (keys %CFG::args)
    {
	if ( $CFG::args{$cfg} )
	{
	    logMsgT ($self,"Updating option ($CFG::args{$cfg}) from arguments",
		     3, $CFG::options{log_file} );
	    $CFG::options{$cfg} = $CFG::args{$cfg};	
	}
    }
}

##############################################################################
## Description: shows Framewors & tools version 		            ##
## Syntax     : showVersions(CURRENT_FUNCTION)				    ##
##############################################################################
sub showVersions
{
    my ($function_caller, $show) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    if ( $show eq "debug" )
    {
	foreach my $tool (sort keys %CFG::versions)
	{
	    my $line = sprintf("%-15s=>   %s", $tool, $CFG::versions{$tool});
	    logMsgT($self, $line, 3, $CFG::options{log_file});
	}
    }
    elsif ( $show eq "normal" )
    {
	foreach my $tool (sort keys %CFG::versions)
	{
	    my $line = sprintf("- %-15s=> %s\n", $tool, $CFG::versions{$tool});
	    print $line;
	}
	print "\n\n";
	exit 1;
    }
}

##############################################################################
## Description: Validates received options from args and config file        ##
## Syntax     : validateOptions(CURRENT_FUNCTION)			    ##
##############################################################################
sub validateOptions
{
    my ($function_caller) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);

    # Validate Execution Mode options
    if 	  ( $CFG::options{mode} eq "full" )
    {
	checkOption($self, "dpm_ids_engine");
    }
    elsif ( $CFG::options{mode} eq "fixtime" )
    {
	checkOption($self, "mode_fixtime_start");
	checkOption($self, "mode_fixtime_stop");
    }
    elsif ( $CFG::options{mode} eq "fixcount" )
    {
	checkOption($self, "mode_fixcount");
    }
    elsif ( $CFG::options{mode} eq "fixsize" )
    {
	checkOption($self, "mode_fixsize");
    }

    if ( $CFG::options{instance_dir} )
    {
	unless ( -d $CFG::options{instance_dir} )
	{
	    logMsgT($self, "Unable to read instance directory ".
		"($CFG::options{instance_dir})", -1, $CFG::options{log_file});
	}
    }
    if ( $CFG::options{cap_file} )
    {
	unless ( $CFG::options{cap_file} =~ m/.*\/.*/)
	{
	    my $path = getcwd;
	    $CFG::options{cap_file} = "$path/$CFG::options{cap_file}";
	}
	unless ( -r $CFG::options{cap_file} )
	{
	    logMsgT($self, "Unable to read PCAP file ".
		"($CFG::options{cap_file})", -1, $CFG::options{log_file});
	}
    }
}

##############################################################################
## Description: Validates received options from args and config file        ##
## Syntax     : checkOption(CURRENT_FUNCTION)				    ##
##############################################################################
sub checkOption
{
    my ($function_caller, $option) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    if ( ! $CFG::options{$option} )
    {
        logMsgT($self, "Missing option '$option'",-1, $CFG::options{log_file});
    }
    else
    {
        logMsgT($self, "Option set : $CFG::options{$option}",
		3, $CFG::options{log_file});
    }    
}

##############################################################################
## Description: Starts PNAF in daemon mode				    ##
## Syntax     : startDaemon(CURRENT_FUNCTION)				    ##
##############################################################################
sub startDaemon
{
    my ($function_caller, $option) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    logMsgT($self,"Daemon started. See ($CFG::options{log_file}) for details",
	    2, $CFG::options{log_file});
    Proc::Daemon::Init;
    $0 = "pnaf_daemon";
    my $pid = getpid();
    writePidFile($self, "daemon", $pid);
    runDaemons($self);
    my $continue = 1;
    $SIG{TERM} = sub { $continue = 0 };
    logMsgT($self, "Daemon started.", 2, $CFG::options{log_file});
    while ($continue)
    {
        logMsgT($self, "Daemon running", 2, $CFG::options{log_file});
	sleep 5;
    }
}

##############################################################################
## Description: Runs Daemons specified on $VG::daemons hash		    ##
## Syntax     : runDaemons(CURRENT_FUNCTION)				    ##
##############################################################################
sub runDaemons
{
    my ($function_caller) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);

    foreach my $daemon (keys%GV::daemons)
    {
	if ( $GV::daemons{$daemon} == 1 )
	{
	    if ( checkDaemon($self,$daemon) == 1 )
	    {
		logMsgT($self, "Ommited new process for ($daemon)",
		    1, $CFG::options{log_file});
		next;	
	    }
	    logMsgT($self, "Daemon ($daemon) enabled. Creating new process",
		    2, $CFG::options{log_file});
	    my $pid = fork;
	    if ( !defined $pid )
	    {
		logMsgT($self, "Unable to create new process for daemon " .
		"	($daemon)", 0, $CFG::options{log_file});
	    }
	    elsif ( $pid == 0 )
	    {
		my $pid = getpid();
		# Child process    
		## Trying to change process name. It works on Linux
		$0 = "pnaf_$daemon";
		logMsgT($self, "Daemon ($daemon) started. PID:($pid)",
			2, $CFG::options{log_file});
		writePidFile($self, $daemon, $pid);
		listenFifo($self, $daemon);
		logMsgT($self, "Listen FIFO process for ($daemon) ".
			"has terminated", 2, $CFG::options{log_file});
		exit 0;
	    }
	    else
	    {
		# parent process
		logMsgT($self, "Back to parent process",
			3, $CFG::options{log_file});
	    }
	    logMsgT($self, "Returning to main daemon",
		    3, $CFG::options{log_file});
	}
    }
}
##############################################################################
## Description: Creates a new process					    ##
## Syntax     : listenFifo(CURRENT_FUNCTION, $type)			    ##
##############################################################################
sub listenFifo
{
    my ($function_caller, $type) = @_;
    my $self  	= getFunctionName($function_caller,(caller(0))[3]);
    my $fifo		= "$CFG::options{log_dir}/$type.fifo";
    logMsgT($self,  "Receiver process started", 2, $CFG::options{log_file});
    while(1)
    {
	if ( open(FIFOFH, "+< $fifo") )
	{
	    logMsgT($self, "Listening incoming tasks on ($fifo)",
		    2, $CFG::options{log_file});
	    while (<FIFOFH>)
	    {
		chomp();
		logMsgT($self, "Task Received ($_) from ($fifo)", 
			2, $CFG::options{log_file});
		executeTask($self,$_);
	    }
	    close(FIFOFH);
	}
	else
	{
	    logMsgT($self, "Unable to read fifo file ($fifo)",
		    0, $CFG::options{log_file});
	}
    }
}

##############################################################################
## Description: Executes task received from fifo	                    ##
## Syntax     : executeTask($FUNCTION_NAME,$TASK)                           ##
##############################################################################
sub executeTask
{
    my ($function_caller, $task) = @_;
    my $self  	= getFunctionName($function_caller,(caller(0))[3]);
    logMsgT($self, "Received Task: ($task)", 2, $CFG::options{log_file});
}

##############################################################################
## Description: Writes the pid file			                    ##
## Syntax     : writePidFile($FUNCTION_NAME, DAEMON, PID)                   ##
##############################################################################
sub writePidFile
{
    my ($function_caller, $daemon, $pid) = @_;
    my $self  	= getFunctionName($function_caller,(caller(0))[3]);
    my $pid_file = "$CFG::options{log_dir}/pnaf_$daemon.pid";
    if ( open(FH,">$pid_file") )
    {
	logMsgT($self, "Adding PID ($pid) to pid file ($pid_file)",
		3, $CFG::options{log_file});
	print FH $pid;
	close(FH);
    }
    else
    {
	logMsgT($self,	"Unable to write PID ($pid) on pid file ($pid_file)",
		0, $CFG::options{log_file});
    }
}

##############################################################################
## Description: Check whether a specified daemon is running                 ##
## Syntax     : checkDaemon($FUNCTION_NAME,DAEMON)                          ##
## Returns    : 0: Process is not running				    ##
## Returns    : 1: Process is running already			  	    ##
##############################################################################
sub checkDaemon
{
    my ($function_caller, $daemon) = @_;
    my $self  	= getFunctionName($function_caller,(caller(0))[3]);
    my $pid_file = "$CFG::options{log_dir}/pnaf_$daemon.pid";
    my @pids;
    if ( open(FHPID,"$pid_file") )
    {
	logMsgT($self, "Reading PID from ($pid_file)",
		3, $CFG::options{log_file});
	my $flag = 0;
	while( <FHPID> )
	{
	    chomp();
	    my $filepid = $_;
	    my $maxpid = getMaxPidNumber($self);
	    if ($filepid > $maxpid || $filepid < 2)
	    {
		logMsgT($self, "Invalid PID from file ($filepid) Max PID ".
			"number($maxpid)", 1, $CFG::options{log_file});
		my $new_check = checkDaemonByName($self, $daemon);
		return $new_check;
	    }
	    logMsgT($self, "PID ($filepid) read from file ($pid_file)",
		    3, $CFG::options{log_file});
	    push(@pids, $filepid);    
	}
	close(FHPID);
	foreach my $pid (@pids)
	{
	    my $pid_exists = `ps aux|grep $pid|grep -v grep|awk '{print \$2}'`;
	    $pid_exists =~ s/\n/ /g;
	    if ( $pid_exists )
	    {
		logMsgT($self,	"PNAF process ($daemon) is running already.".
			" PID ($pid_exists)", 1, $CFG::options{log_file});
		$flag = 1;
	    }
	}
	if ( $flag == 1 )
	{
	    logMsgT($self,  "Some PNAF process are running already. ".
		    "Kill them first",  0, $CFG::options{log_file});
	    return 1;
	}
	else
	{
	    logMsgT($self,"No PNAF pids found", 3, $CFG::options{log_file});
	    return 0;
	}
    }
    else
    {
	logMsgT($self, "Unable to find pid file ($pid_file) ".
		"Searching process name..", 1, $CFG::options{log_file});
	my $new_check = checkDaemonByName($self, $daemon);
	return $new_check;
    }
}

##############################################################################
## Description: Check whether a specified daemon is running                 ##
## Syntax     : checkDaemonByName($FUNCTION_NAME,DAEMON)                    ##
## Returns    : 0: Process is not running				    ##
## Returns    : 1: Process is running already				    ##
##############################################################################
sub checkDaemonByName
{
    my ($function_caller, $daemon) = @_;
    my $self  	= getFunctionName($function_caller,(caller(0))[3]);
    # If no PID file, then check manually
    logMsgT($self, "Checking PNAF ($daemon) processes by alternative method ".
	    "(ps aux)", 3, $CFG::options{log_file});
    print ">>> ps aux|grep pnaf_$daemon |grep -v grep |awk '{print \$2}'\n\n";
    my $pids = `ps aux| grep pnaf_$daemon | grep -v grep |awk '{print \$2}'`;

    $pids =~ s/\n/ /g;
    logMsgT($self, "PNAF PIDS found: ($pids)", 3, $CFG::options{log_file});
    if ( $pids )
    {
        logMsgT($self, "It seems PNAF ($daemon) is running already. PIDs: (".
		"$pids)", 1, $CFG::options{log_file});
        return 1;
    }
    else
    {
        logMsgT($self,"No PNAF processes running", 3, $CFG::options{log_file});
        return 0;
    }
}
##############################################################################
## Description: Gets the maximum PID value		 	            ##
## Syntax     : getMaxPidNumber($FUNCTION_NAME,DAEMON)                      ##
##############################################################################
sub getMaxPidNumber
{
    my ($function_caller, $daemon) = @_;
    my $self  	= getFunctionName($function_caller,(caller(0))[3]);
    if ( open(FH, "$GV::pid_max_file") )
    {
	my $pidmax;
	while( <FH> )
	{
	    chomp();
	    $pidmax .= $_;
	}
	close(FH);
	logMsgT($self, "Max PID number found on ($GV::pid_max_file) is ".
		"($pidmax)", 3, $CFG::options{log_file});
	return $pidmax;
    }
    else
    {
	logMsgT($self, "Unable to read ($GV::pid_max_file) Using default ".
		"($GV::pidmax_def)", 3, $CFG::options{log_file});
	return $GV::pidmax_def;
    }    

}

##############################################################################
## Description: check whether a directory exists or not	 	            ##
## Syntax     : checkDir($FUNCTION_NAME,DIR)		                    ##
##############################################################################
sub checkDir
{
    my ($function_caller, $dir) = @_;
    my $self  	= getFunctionName($function_caller,(caller(0))[3]);
    my $check = 0;
    $check = 1 if ( -d $dir );
    return $check;
}

##############################################################################
## Description: Stores the content of var CONTENT into OUTFILE
## Syntax     : saveContent(CURRENT_FUNCTION, CONTENT, OUTFILE)
##############################################################################
sub saveContent
{
    my ($function_caller, $content, $outfile) = @_;
    my $self  	= getFunctionName($function_caller,(caller(0))[3]);
    logMsgT($self,"Dumping content into file ($outfile)",
	    3, $CFG::options{log_file});
    if ( $content )
    {
        if ( open(FHO,">$outfile") )
	{
	    print FHO $content;	
	    close(FHO);
	}
	else
	{
	    logMsgT($self,"Unable to store content on file ($outfile)",
		    0, $CFG::options{log_file});
	}
    }
    else
    {
	logMsgT($self,"Empty content for file ($outfile)",
		0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Creates Pipe fle from from hash		                    ##
## Syntax     : writePipeFromHash($FUNCTION_NAME, DATAHASH, OUTFILE)        ##
##############################################################################
sub writePipeFromHash
{
    my ($function_caller, $datahash, $outfile) = @_;
    my $self  	= getFunctionName($function_caller,(caller(0))[3]);
    logMsgT($self,"Creating pipe file ($outfile)", 3, $CFG::options{log_file});
    if ( open(FH_FPFH,">$outfile") )
    {
	foreach my $key ( keys%$datahash )
	{
	    print FH_FPFH "$key|$datahash->{$key}\n";
        }
	close(FH_FPFH);
    }
    else
    {
	logMsgT($self,"Unable to write on output file ($outfile)",
		0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Creates JSON file from hash		                    ##
## Syntax     : writeJsonFile($FUNCTION_NAME, DATAHASH, OUTFILE)            ##
##############################################################################
sub writeJsonFile
{
    my ($function_caller, $datahash, $outfile) = @_;
    my $self = getFunctionName($function_caller,(caller(0))[3]);
    my $json = encode_json $datahash;
    logMsgT($self,"Creating JSON file ($outfile)", 3, $CFG::options{log_file});
    if ( open(FHJSON,">$outfile") )
    {
	print FHJSON $json;	
	close(FHJSON);
    }
    else
    {
	logMsgT($self,"Unable to create JSON file ($outfile)",
		0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Inserts content into a file by matching a replace pattern 
## Syntax     : insertContent(CURRENT_FUNCTION, INFILE, OUTFILE, DATA, PATTERN)
##############################################################################
sub insertContent
{
    my ($function_caller, $infile, $outfile, $json, $var ) = @_;
    my $self  	= getFunctionName($function_caller,(caller(0))[3]);
    if ( $json )
    {
	if ( open(FH_IN,"$infile") )
	{
	    my $content;
	    while ( <FH_IN> )
	    {
		$content .= $_;
	    }
	    close(FH_IN);
	    if ( open(FH_OUT,">$outfile") )
	    {
		logMsgT($self, "Inserting content into file ($outfile)",
			3, $CFG::options{log_file});	
		$content =~ s/$var/$json/g;
		print FH_OUT $content;
		close(FH_OUT)
	    }
	    else
	    {
		logMsgT($self, "Unable to write output file ($outfile)",
				0, $CFG::options{log_file});	
	    }
	}
	else
	{
	    logMsgT($self, "Unable to read input file ($infile)",
			    0, $CFG::options{log_file});	
	}
    }
    else
    {
        logMsgT($self, "JSON string is empty.", 0, $CFG::options{log_file});	
    }
}
##############################################################################
## Description: Gets the parsing format from options/cfg file. Returns a hash 
## Syntax     : getLogFields(CURRENT_FUNCTION, TOOL)
##############################################################################
sub getLogFields
{
    my ($function_caller, $tool ) = @_;
    my $self = getFunctionName($function_caller,(caller(0))[3]);
    my %field;
    if ( $tool )
    {
	my $cntf = 0;
	my $lftool = "lf_$tool";
	logMsgT($self, "($tool) format found: $CFG::options{$lftool}",
		3,$CFG::options{log_file});
	my @log = split(/\|/, $CFG::options{"lf_$tool"}); 
	foreach my $lf ( @log )
	{
	    logMsgT($self, "($tool) log field found: $lf",
		    3, $CFG::options{log_file});
	    if 	  ( $lf =~ m/^dm$/ )
	    {
		$field{"Domains"} 		= $cntf;
	    }
	    elsif ( $lf =~ m/^ts$/ )
	    {
		$field{"Timestamp"}		= $cntf;
	    }
	    elsif ( $lf =~ m/^pt$/ )
	    {
		$field{"Protocols"}		= $cntf;
	    }
	    elsif ( $lf =~ m/^hmt$/ )
	    {
		$field{"Methods"}  		= $cntf;
	    } 
	    elsif ( $lf =~ m/^rs$/ )
	    {
		$field{"Resources"} 		= $cntf;
	    }
	    elsif($lf =~ m/^hua$/ )
	    {
		$field{"User Agents"}		= $cntf;
	    }
	    elsif($lf =~ m/^hpx$/ )
	    {
		$field{"Proxys"} 		= $cntf;
	    }
	    elsif ( $lf =~ m/^hsc$/ )
	    {
		$field{"Status Codes"} 		= $cntf;
	    }
	    elsif ( $lf =~ m/^hrp$/ )
	    {
		$field{"Response Phrases"}	= $cntf;
	    }
	    elsif ( $lf =~ m/^hrb$/ )
	    {
		$field{"Response Bytes"} 	= $cntf;
	    }
	    elsif ( $lf =~ m/^us$/ )
	    {
		$field{"useconds"} 		= $cntf;
	    }
	    elsif ( $lf =~ m/^si$/ )
	    {
		$field{"Clients"} 		= $cntf;
	    }
	    elsif ( $lf =~ m/^sp$/ )
	    {
		$field{"Client Ports"}		= $cntf;
	    }
	    elsif ( $lf =~ m/^di$/ )
	    {
		$field{"Servers"} 		= $cntf;
	    }
	    elsif ( $lf =~ m/^dp$/ )
	    {
		$field{"Server Ports"} 		= $cntf;
	    }
	    elsif ( $lf =~ m/^sip$/ )
	    {
		$field{"Source IPs"} 		= $cntf;
	    }
	    elsif ( $lf =~ m/^spr$/ )
	    {
		$field{"Source Ports"}		= $cntf;
	    }
	    elsif ( $lf =~ m/^dip$/ )
	    {
		$field{"Destination IPs"} 	= $cntf;
	    }
	    elsif ( $lf =~ m/^dpr$/ )
	    {
		$field{"Destination Ports"} 	= $cntf;
	    }
	    elsif ( $lf =~ m/^dr$/ )
	    {
		$field{"Flow Direction"} 	= $cntf;
	    }
	    elsif ( $lf =~ m/^pas$/ )
	    {
		$field{"Asset"} 		= $cntf;
	    }
	    elsif ( $lf =~ m/^pvl$/ )
	    {
		$field{"Vlan"} 			= $cntf;
	    }
	    elsif ( $lf =~ m/^ppr$/ )
	    {
		$field{"Port"} 			= $cntf;
	    }
	    elsif ( $lf =~ m/^ppt$/ )
	    {
		$field{"Proto"}			= $cntf;
	    }
	    elsif ( $lf =~ m/^psv$/ )
	    {
		$field{"Service"}		= $cntf;
	    }
	    elsif ( $lf =~ m/^psi$/ )
	    {
		$field{"Service Info"} 		= $cntf;
	    }
	    elsif ( $lf =~ m/^pds$/ )
	    {
		$field{"Distance"} 		= $cntf;
	    }
	    else
	    {
		$field{"Unknown Field"} 	= $cntf;
	    }
	    $cntf++;
	}
	foreach my $data (sort { $field{$a} <=> $field{$b} } keys%field )
	{
	    logMsgT($self,"($tool) $data - Field # $field{$data}",
		    3, $CFG::options{log_file});	    
	}
    }
    else
    {
	logMsgT($self,"Invalid log field request. Empty tool name ($tool)",
		0, $CFG::options{log_file});	    
    }
    return %field;
}
##############################################################################
## Description: Gets the parsing format from options/cfg file. Returns a hash 
## Syntax     : getFields(CURRENT_FUNCTION, TOOL)
##############################################################################
sub getFields
{
    my ($function_caller, $var, $fs ) = @_;
    my $self = getFunctionName($function_caller,(caller(0))[3]);
    my %field;
    if ( $var && $fs )
    {
	my $cntf = 0;
	logMsgT($self, "Parsing log fields from ($var)",
		3,$CFG::options{log_file});
	my @log = split(/$fs/, $var); 
	foreach my $lf ( @log )
	{
	    if ( $lf =~ m/.+/)
	    {
		logMsgT($self, "log field found: $lf", 
			3, $CFG::options{log_file});
		$field{$lf} = $cntf;
		$cntf++;
	    }
	}
    }
    else
    {
	logMsgT($self,"Invalid log field request. FS and VAR needed ",
		0, $CFG::options{log_file});	    
    }
    return %field;
}
##############################################################################
## Description: Reads a file and returns its content as string              ##
## Syntax     : getFilecontent($FUNCTION_NAME, FILE)i	  		    ##
##############################################################################
sub getFileContent
{
    my ($function_caller, $file) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    my $content;
    logMsgT($self,"Reading content of file ($file)",
	    3, $CFG::options{log_file});
    if ( open(FH_FILEREAD,$file) )
    {
	while ( <FH_FILEREAD>)
	{
	    $content .= $_;
	}
	close(FH_FILEREAD);
    }
    else
    {
	logMsgT($self,"Unable to read file ($file)",
		0, $CFG::options{log_file});
    }
    return $content;
}
##############################################################################
## Description: Get tokens from a string. Returns a hash
## Syntax     : getTokens(CURRENT_FUNCTION, STRING)
##############################################################################
sub getTokens
{
    my ($function_caller, $string) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    my %tokens;
    logMsgT($self,"Parsing tokens from ($string)", 3,$CFG::options{log_file});
    my $decoded = uri_decode($string);
    my $tokenizer = String::Tokenizer->new($decoded,',.:/&)(=-~?_+;!%$#');
    my @tok = $tokenizer->getTokens();
    foreach my $t (@tok)
    {
	if ( $t =~ m/[A-Za-z0-9]/)
	{
	    if    ( $t =~ m/^[A-Za-z]+$/)
	    {
		$tokens{alpha}{word}{$t}++;
	    }
	    elsif ( $t =~ m/^[0-9]+$/)
	    {
		$tokens{alpha}{number}{$t}++;
	    }
	    else
	    {
		$tokens{alpha}{alphanum}{$t}++;
	    }
	}
	else
	{
	    $tokens{symbols}{$t}++;
	}
    }
    return %tokens;
}
##############################################################################
## Description: Validates received toolname			            ##
## Syntax     : validateParser(CURRENT_FUNCTION)			    ##
##############################################################################
sub validateParser
{
    my ($function_caller, $parser) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    if ( $parser )
    {
	if ( $CFG::parsers{$parser} )
	{
	    if ( $CFG::parsers{$parser} =~ m/(on|1)/ )
	    {
		return 1;
	    }
	    else
	    {
		logMsgT($self,"Parser ($parser) is set as (disabled)",
			1,$CFG::options{log_file});
	    }
	}
	else
	{
	    logMsgT($self,"Invalid parser ($parser)",1,$CFG::options{log_file});
	}
    }
    else
    {
	logMsgT($self,"Empty parser name", 0,$CFG::options{log_file});
    }
    return 0;
}
##############################################################################
## Description: Reads Suricata's EVE json returns its content as string     ##
## Syntax     : getJsonEvents($FUNCTION_NAME, FILE)	  		    ##
##############################################################################
sub getJsonEvents
{
    my ($function_caller, $file, $mode) = @_;
    my $self  = getFunctionName($function_caller,(caller(0))[3]);
    logMsgT($self,"Reading content of EVE Json file ($file)",
	    3, $CFG::options{log_file});
    if ( open(FH_JSONFILE,$file) )
    {
	if ( $mode eq "hash" )
	{
	    # Since decoders reach 'out of memory' when processing huge json 
	    # files, then the parsing is done by line and stored into a hash
	    my %datahash;
	    my $cnt = 1;
	    while ( <FH_JSONFILE>)
	    {
		$_ =~ s/"category":""/"category":"Uncategorized"/;
		my $jsonhash = parse_json ($_); # More efficient 
		foreach my $key (keys%$jsonhash)
		{
		    $datahash{"Event$cnt"}{$key} = $jsonhash->{$key};
		}
		$cnt++;
	    }
	    $cnt--;
	    logMsgT($self," |-- ($cnt) events processed from JSON file ($file)",
		    2, $CFG::options{log_file});
	    close(FH_JSONFILE);
	    return \%datahash;
	}
	elsif ( $mode eq "string" )
	{
	    my $content;
	    $content = "{";
	    my $cnt = 1;
	    while ( <FH_JSONFILE>)
	    {
		$_ =~ s/"category":""/"category":"Uncategorized"/;
		$content .=  "\"Event$cnt\" : $_,";
		$cnt++;
	    }
	    $content .= "--flag--}";
	    $content =~ s/,--flag--//g;
	    #my $datahash = decode_json $content;  # Low performance
	    my $datahash = parse_json ($content); # More efficient 
	    close(FH_JSONFILE);
	    return $datahash;
	}
	else
	{
	    logMsgT($self,"Invalid mode ($mode)", 0, $CFG::options{log_file});
	    close(FH_JSONFILE);
	}
    }
    else
    {
	logMsgT($self,"Unable to read file ($file)",
		0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Attaches payloads into a hash passed as argument  	    ##
## Syntax     : getPayloads($FUNCTION_NAME, \%HASHEVT, $U2FILE)		    ##
##############################################################################
sub getPayloads
{
    my ($function_caller, $hash, $file) = @_;
    my $self = getFunctionName($function_caller,(caller(0))[3]);
    my %tmphash;
    unless ( $file )
    {
	logMsgT($self,"Unable to read Unified2 file ($file)",
		0, $CFG::options{log_file});
	return;
    }
    logMsgT($self,"Decoding Unified2 file ($file)",2,$CFG::options{log_file});
    my $UF_Data = openSnortUnified($file);
    unless ($UF_Data)
    {
	logMsgT($self,"Unable to read Unified2 file ($file)",
		0, $CFG::options{log_file});
	return;
    }
    my $cnt       = 0;
    my $cntNullId = 0;
    my $lastId    ;
    while ( my $record = readSnortUnified2Record() )
    {
	my $flow = '';
	if ($record->{'sip'} && $record->{'dip'})
	{
	    $lastId = $record->{'event_id'};
	    if ( $record->{'sp'} && $record->{'dp'})
	    {
		$flow = dec2ip($self,$record->{'sip'})."_".$record->{'sp'}."_".
			dec2ip($self,$record->{'dip'})."_".$record->{'dp'};
	    }
	    else
	    {
		$flow = dec2ip($self,$record->{'sip'}) . "_" .
		        dec2ip($self,$record->{'dip'});
	    }
	    $flow .=  "_". $record->{'tv_sec'} . "." . $record->{'tv_usec'};
	    $tmphash{$record->{'event_id'}}{flow} = $flow; 
	}
	else
	{
	    if ( $record->{'pkt'} && $record->{'pkt_len'} )
	    {
		# The following fix handles the null eventID in unified2
		# files created by suricata when processing malformed pcaps.
		# During the tests, I've found this behaviour processing
		# IPV6 packets.
		# Thus, since the unified2 format is as follows:
		# 	record: evtId=1
		# 	packet: evtId=1
		# 	record: evtId=2
		# 	packet: evtId=2...
		# then, lastId variable contains the actual event Id.
		# Otherwise it uses the valid eventId within the record.
		my $evtId;
		if ( $record->{'event_id'}  == 0)
		{
		    $evtId = $lastId;
		    $cntNullId++;
		}
		else
		{
		    $evtId = $record->{'event_id'};
		}
		if ( $hash->{$tmphash{$evtId}{flow}}{pkt_len} )
		{
		    $hash->{$tmphash{$evtId}{flow}}{pkt_len} +=
			$record->{'pkt_len'}; 
		}
		else
		{
		    $hash->{$tmphash{$evtId}{flow}}{pkt_len} =
			$record->{'pkt_len'}; 
		}
		if ( $hash->{$tmphash{$evtId}{flow}}{pkt} )
		{
		    $hash->{$tmphash{$evtId}{flow}}{pkt} .= "\n".
		    xd $record->{'pkt'},{ 
		    row  => 16,# print 10 bytes in a row
		    cols => 2, # split in 2 column groups, separated with<hsp?>
		    hsp  => 0, # add 2 spaces between hex columns
		    csp  => 0, # add 1 space between char columns 
		    hpad => 1, # pad each hex byte with 1 space (ex: " 00" )
		    cpad => 0, # pad each char byte with 1 space
		    };  
		}
		else
		{
		    $hash->{$tmphash{$evtId}{flow}}{pkt} = 
		    xd $record->{'pkt'},{ 
		    row  => 16,# print 10 bytes in a row
		    cols => 2, # split in 2 column groups, separated with<hsp?>
		    hsp  => 0, # add 2 spaces between hex columns
		    csp  => 0, # add 1 space between char columns 
		    hpad => 1, # pad each hex byte with 1 space (ex: " 00" )
		    cpad => 0, # pad each char byte with 1 space
		    };  
		}
	    }
	    else
	    {
		logMsgT($self,"No enough information for unified2 EventId ".
			"($record->{'event_id'})",1,$CFG::options{log_file});
	    }
	    $cnt++;
	}
    }
    closeSnortUnified();
    if ( $cntNullId > 0 )
    {
	logMsgT($self,"Possible malformed PCAP. Unified2 file ($file) "   . 
		" contains ($cntNullId) events with null eventId and they ".
		"have been fixed.", 1, $CFG::options{log_file});
    }
    logMsgT($self,"Parsed ($cnt) payloads from Unified2 file ($file) ",
		2, $CFG::options{log_file});
}
##############################################################################
## Description: Creates payload files				  	    ##
## Syntax     : writePayloadFiles($FUNCTION_NAME, \%HASH, $OUTDIR)	    ##
##############################################################################
sub writePayloadFiles
{
    my ($function_caller, $hash, $outdir, $prefix) = @_;
    my $self = getFunctionName($function_caller,(caller(0))[3]);
    if ( $hash )
    {
	foreach my $key (keys%$hash)
	{
	    if ( open(FH_PAY,">$outdir/$prefix$key") )
	    {
		print FH_PAY "Payload size : $hash->{$key}{pkt_len}\n";
		print FH_PAY "Payload data :\n$hash->{$key}{pkt}";
		close(FH_PAY);
	    }
	    else
	    {
		logMsgT($self,"Unable to write payload file " .
			"($outdir/$prefix$key)", 0, $CFG::options{log_file});
	    }
	}
    }
    else
    {
	logMsgT($self,"No payload hash specified", 0, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Converts Decimal to dotted IP addr format	  	    ##
## Syntax     : dec2ip($FUNCTION_NAME, $DECIP)				    ##
##############################################################################
sub dec2ip
{
    my ($function_caller, $decip) = @_;
    my $self = getFunctionName($function_caller,(caller(0))[3]);
    if ( $decip =~ m/^\d+$/ )
    {
	return join '.', unpack 'C4', pack 'N', $decip;
	#my $dotquad = inet_ntoa(pack("N",shift||$decip));
	#return $dotquad;
    }
    elsif ( $decip =~ m/[0-9abcdef]+:/ )
    {
	return $decip;
    }
    else
    {
	logMsgT($self,"Invalid decimal IP format ($decip)",
		1, $CFG::options{log_file});
    }
}
##############################################################################
## Description: Returns proto name	  	    			    ##
## Syntax     : getProto($FUNCTION_NAME, $DECIP)			    ##
##############################################################################
sub getProto
{
    my ($function_caller, $pnumber) = @_;
    my $self = getFunctionName($function_caller,(caller(0))[3]);
    if ( $pnumber  == 1 )
    {
	return "icmp";
    }
    elsif ( $pnumber  == 6 )
    {
	return "tcp";
    }
    elsif ( $pnumber  == 17 )
    {
	return "udp";
    }
    else
    {
	return "Protocol_$pnumber";
    }
}
##############################################################################
##############################################################################
1;


