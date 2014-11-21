#!/usr/bin/perl -w
#############################################################################
# PASSIVE NETWORK AUDIT FRAMEWORK                                           
# Version 0.1.0                                                            
# By Javier Santillan [2014]                                               
# --------------------------------------------------------------------------
#                                                                            
# File          : PNAF DVM module                                        
# Description   : Standard variables and functions for Data Visualization
#                                                                            
##############################################################################

use strict;
use warnings;
use Pnaf::Core;

##############################################################################  
## Description: Creates an HTML file with a JSON tree viewer from JSON string
## Syntax     : createJsonTreeView1(CURRENT_FUNCTION, MODULE, JSONDATA) 
##############################################################################  
sub createJsonTreeView1
{
    my ($function_caller, $module, $jsondata, $dir) = @_;
    my $self   = getFunctionName($function_caller,(caller(0))[3]);
    my $outdir = "$dir/view1";
    my $index_t = "$CFG::options{dvm_web_dir}/json/view1/default.htm";
    my $html 	= "$outdir/$module.html";
    my $title	;
    my $subt	;
    $module =~ m/([^_]+)_([^_]+)/;
    $title	= uc($1). " " . uc($2) . " " . "Data" ;
    logMsgT($self,"Creating HTML file ($html) ",
			    3,$CFG::options{log_file});
    insertContent($self, $index_t, $html, $title   , "JSON_TITLE");
    insertContent($self, $html   , $html, $jsondata, "JSON_DATA");     
}
##############################################################################  
## Description: Creates an HTML file with a JSON tree viewer from JSON string
## Syntax     : createJsonTreeView2(CURRENT_FUNCTION, MODULE, JSONDATA) 
##############################################################################  
sub createJsonTreeView2
{
    my ($function_caller, $module, $jsondata, $dir) = @_;
    my $self   = getFunctionName($function_caller,(caller(0))[3]);
    my $outdir = "$dir/view2";
    my $index_t = "$CFG::options{dvm_web_dir}/json/view2/index_template.html";
    my $js_t	= "$CFG::options{dvm_web_dir}/json/view2/js/js_template.js";
    my $html 	= "$outdir/$module.html";
    my $js	= "$outdir/js/$module.js";
    my $title	;
    my $subt	;
    $module =~ m/([^_]+)_([^_]+)_([^_]+)/;
    $title	= uc($1). " " . uc($2) . " " . "Data" ;
    $subt	= uc($3) ;
    logMsgT($self,"Creating HTML file ($html) ",
			    3,$CFG::options{log_file});
    logMsgT($self,"Creating JS file ($js) ",
			    3,$CFG::options{log_file});
    insertContent($self, $index_t, $html, "$module.js", "JSON_EDIT");
    insertContent($self, $html   , $html, $title   , "JSON_TITLE");
    insertContent($self, $html   , $html, $subt    , "JSON_SUBTITLE");
    insertContent($self, $js_t   , $js  , $jsondata, "JSON_DATA");     
}
##############################################################################  
## Description: Creates an HTML file with a JSON tree viewer from JSON hash   
## Syntax     : createJsonTreeGroup(CURRENT_FUNCTION, MODULE, JSONHASH, OUTDIR) 
##############################################################################  
sub createJsonTreeGroup
{
    my ($function_caller, $module, $hash, $dir) = @_;
    my $self   = getFunctionName($function_caller,(caller(0))[3]);
    my $outdir = "$dir/summary";
    my $html_t;
    my $html;
    if ( $module =~ m/(npe_str|npe_hash)/ )
    {	
	$html_t = "$CFG::options{dvm_web_dir}/summary/template_npe.html";
	$html   = "$outdir/$module.html";
    }
    elsif ( $module =~ m/(dataset)/ )
    {	
	$html_t = "$CFG::options{dvm_web_dir}/json/summary/dataset.html";
	$html   = "$outdir/$module.html";
    }
    elsif ( $module =~ m/(auditSummary)/ )
    {	
	$html_t = "$CFG::options{dvm_web_dir}/json/summary/auditSummary.html";
	$html   = "$outdir/$module.html";
    }
    elsif ( $module =~ m/(auditSoftware)/ )
    {	
	$html_t = "$CFG::options{dvm_web_dir}/json/summary/auditSoftware.html";
	$html   = "$outdir/$module.html";
    }
    elsif ( $module =~ m/(auditTracking)/ )
    {	
	$html_t = "$CFG::options{dvm_web_dir}/json/summary/auditTracking.html";
	$html   = "$outdir/$module.html";
    }
    elsif ( $module =~ m/(auditOutput)/ )
    {	
	$html_t = "$CFG::options{dvm_web_dir}/json/summary/auditOutput.html";
	$html   = "$outdir/$module.html";
    }
    else
    {
	logMsgT($self,"Invalid JSON group module ($module)",
				0,$CFG::options{log_file});
    }
    logMsgT($self,"Creating HTML file ($html) from ($html_t)",
			    3,$CFG::options{log_file});
    logMsgT($self,"Output HTML file ($html)",
			    2,$CFG::options{log_file});
    # Creating HTML from template
    insertContent($self, $html_t, $html, "html", "html");     
    foreach my $json ( keys%$hash)
    {
	if ($json =~ m/TITLE/)
	{
	    insertContent($self,$html,$html,$hash->{$json},$json);
	}
	else
	{
	    logMsgT($self,"Encoding data from ($json)",
		    3,$CFG::options{log_file});
	    my $ptr = "JSON_" . uc($json); ## String to replace within template
	    insertContent($self,$html,$html,encode_json $hash->{$json}, $ptr);
	}
    }
}
##############################################################################
1;

