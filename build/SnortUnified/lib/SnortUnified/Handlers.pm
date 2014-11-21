package SnortUnified::Handlers;
#########################################################################################
#  $VERSION = "SnortUnified Parser - Copyright (c) 2007 Jason Brvenik";
# 
# A Perl module to make it easy to work with snort unified files.
# http://www.snort.org
# 
# callback handling routines
#
# 
#########################################################################################
# 
#
# The intellectual property rights in this program are owned by 
# Jason Brvenik, Inc.  This program may be copied, distributed and/or 
# modified only in accordance with the terms and conditions of 
# Version 2 of the GNU General Public License (dated June 1991).  By 
# accessing, using, modifying and/or copying this program, you are 
# agreeing to be bound by the terms and conditions of Version 2 of 
# the GNU General Public License (dated June 1991).
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
# See the GNU General Public License for more details.
#        
# You should have received a copy of the GNU General Public License 
# along with this program; if not, write to the 
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, 
# Boston, MA  02110-1301  USA 
#            
# 
#
my $class_self;

BEGIN {
   $class_self = __PACKAGE__;
   $VERSION = "1.6devel20071118";
}

my $LICENSE = "GNU GPL see http://www.gnu.org/licenses/gpl.txt for more information.";
sub Version() { "$class_self v$VERSION - Copyright (c) 2007 Jason Brvenik" };
sub License() { Version . "\nLicensed under the $LICENSE" };

@ISA = qw(Exporter);
@EXPORT = qw();
@EXPORT_OK = qw(
    $debug
    register_handler
    register_pcre
    register_qualifier
    unregister_handler
    unregister_qualifier
    show_handlers
    show_qualifiers
    exec_handler
    exec_qualifier
);

%EXPORT_TAGS = (
               ALL => [@EXPORT, @EXPORT_OK],
);

my $HANDLERS = {};
my $QUALIFIERS = {};


###############################################################
# Register pcre qualifier
###############################################################
sub register_pcre($$$) {
    my $gen = shift;
    my $sid = shift;
    my $pcre = shift;
    my $t = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    debug("Registering a pcre qualifier for " . $gen . ":" . $sid);

    # XXX - Need to put in test code for valid pcre
    push(@{$QUALIFIERS->{'PCRE'}->{$gen}->{$sid}}, $pcre);

    return 1;
}

###############################################################
# Register qualifier
###############################################################
sub register_qualifier($$$$) {
    my $type = shift;
    my $gen = shift;
    my $sid = shift;
    my $sub = shift;
    
    debug("Registering a qualification handler for " . $type . ":" . $gen . ":" . $sid);

    push(@{$QUALIFIERS->{$type}->{$gen}->{$sid}}, $sub);
}

###############################################################
# UN Register qualifier
###############################################################
sub unregister_qualifier($$$) {
    my $type = shift;
    my $gen = shift;
    my $sid = shift;

    debug("UN Registering handlers for " . $type . ":" . $gen . ":" . $sid);
    undef $QUALIFIERS->{$type}->{$gen}->{$sid};

}

###############################################################
# Show qualifiers
###############################################################
sub show_qualifiers() {
    foreach my $type (keys %{$QUALIFIERS}){
        print("Qualifier for type " . $type . ":\n");
        foreach my $gen (keys %{$QUALIFIERS->{$type}}){
            print("\tgen " . $gen . ":\n");
            foreach my $sid (keys %{$QUALIFIERS->{$type}->{$gen}}) {
                print("\t\tsid " . $sid . ":\n");
                foreach my $hdlr (@{$QUALIFIERS->{$type}->{$gen}->{$sid}}) {
                    print("\t\t\t" . $type . ":" . $gen . ":" . $sid . " is " . $hdlr . "\n");
                }
            }
        }
    }
}

###############################################################
# Exec qualifier
# Walks the list of registered qualifiers and ands the results
# successful qualifications need to return > 0 for this to work
###############################################################
# Basically specific evaluations get to override generic ones
# and PCRE gets an equal shot but cannot override
###############################################################
sub exec_qualifier($$$$) {
    my $type = shift;
    my $gen = shift;
    my $sid = shift;
    my $rec = shift;
    my $retval = 1;
    my $pcreretval = 1;
    my $ret_eval = 0;

    if ( defined $QUALIFIERS->{0}->{0}->{0} ) {
        debug("Executing qualifier for 0 0 0");
        foreach my $block (@{$QUALIFIERS->{0}->{0}->{0}}) {
            last if ( $retval < 1 );
            debug("Executing qualifier " . $block);
            eval { $ret_eval = &$block($rec); };
            $retval = $retval & $ret_eval;
        }
    }

    $gen = '' unless ( $gen );
    $sid = '' unless ( $sid );
    if ( defined $QUALIFIERS->{0}->{$gen}->{$sid} ) {
        # A decision was made to operate on this GEN:SID, reset retval.
        $retval = 1;
        debug("Executing qualifier for 0 :" . $gen . ":" . $sid);
        foreach my $block (@{$QUALIFIERS->{0}->{$gen}->{$sid}}) {
            last if ( $retval < 1 );
            debug("Executing qualifier " . $block);
            if ($debug) {
                $ret_eval = &$block($rec);
            } else {
                eval { $ret_eval = &$block($rec); };
            }
            $retval = $retval & $ret_eval;
        }
    }

    if ( defined $QUALIFIERS->{$type}->{$gen}->{$sid} ) {
    
        # A decision was made to operate on this GEN:SID, reset retval.
        $retval = 1;

        debug("Executing qualifier for " . $type . ":" . $gen . ":" . $sid);
    
        foreach my $block (@{$QUALIFIERS->{$type}->{$gen}->{$sid}}) {
            last if ( $retval < 1 );
            debug("Executing qualifier " . $block);
            if ($debug) {
                $ret_eval = &$block($rec);
            } else {
                eval { $ret_eval = &$block($rec); };
            }
            $retval = $retval & $ret_eval;
        }
    }
    
    if ( defined $QUALIFIERS->{'PCRE'}->{$gen}->{$sid} && defined $rec->{'pkt'} ) {

        debug("Handling PCRE for" . $gen . ":" . $sid);

        foreach my $pcre (@{$QUALIFIERS->{'PCRE'}->{$gen}->{$sid}}) {
            last if ( $retval < 1 );
            debug("checking " . $pcre);
            $ret_eval = ( $rec->{'pkt'} =~ m/($pcre)/ );
            $retval = $retval & $ret_eval;
        }
    }

    return $retval;
}

###############################################################
# Register handlers
###############################################################
sub register_handler($$) {
    my $hdlr = shift;
    my $sub = shift;
    chomp $hdlr;
    debug("Registering a handler for " . $hdlr);
    push(@{$HANDLERS->{$hdlr}}, $sub);
}

###############################################################
# UN Register handlers
###############################################################
sub unregister_handler($) {
    my $hdlr = shift;
    chomp $hdlr;
    debug("UN Registering a handler for " . $hdlr);
    undef $HANDLERS->{$hdlr};
}

###############################################################
# Show handlers
###############################################################
sub show_handlers() {
    foreach my $hdlr (keys %{$HANDLERS}) {
        foreach my $reg (@{$HANDLERS->{$hdlr}}) {
            print("Handler " . $hdlr . " is " . $reg . "\n");
        }
    }
}

###############################################################
# Run handlers
###############################################################
sub exec_handler {
    my $hdlr = shift;
    my $data = shift;
    chomp $hdlr;
    debug("Checking handler " . $hdlr);
    if ( defined $HANDLERS->{$hdlr} ) {
        debug("Executing handlers " . $hdlr);
        foreach my $sub (@{$HANDLERS->{$hdlr}}) {
            debug("Executing handlers " . $sub);
            eval { &$sub($data); }
        }
    } else {
        debug("No registered handler for " . $hdlr);
    }
}

###############################################################
# sub debug() {
# Prints message passed to STDERR wrapped in line markers
#
# Parameters: $msg is the debug message to print
#
# Returns: Nothing
#
# TODO:
###############################################################
sub debug($) {
    return unless $debug;
    my $msg = $_[0];
        my $package = undef;
        my $filename = undef;
        my $line = undef;
        ($package, $filename, $line) = caller();
    print STDERR $filename . ":" . $line . " : " . $msg . "\n";
}

1;
