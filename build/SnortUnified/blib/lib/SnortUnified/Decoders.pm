package Decoders;

#########################################################################################
#  $VERSION = "SnortUnified Parser - Copyright (c) 2007 Jason Brvenik";
# 
# A Perl module to make it easy to work with snort unified files.
# http://www.snort.org
# 
# Decoding routines for packets
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
#########################################################################################

my $class_self;

BEGIN {
   $class_self = __PACKAGE__;
   $VERSION = "1.6devel20071001";
}
my $LICENSE = "GNU GPL see http://www.gnu.org/licenses/gpl.txt for more information.";
sub Version() { "$class_self v$VERSION - Copyright (c) 2007 Jason Brvenik" };
sub License() { Version . "\nLicensed under the $LICENSE" };

@ISA = qw(Exporter);
@EXPORT = qw();
@EXPORT_OK = qw(
                decodeIPOptions
                decodeTCPOptions
);

%EXPORT_TAGS = (
               ALL => [@EXPORT, @EXPORT_OK],
               IP_decoders => [qw(
                                   decodeIPOptions
                                 )
                              ],
               TCP_decoders => [qw(
                                   decodeTCPOptions
                                  )
                               ],
               UDP_decoders => [qw(
                                  )
                               ],
               ICMP_decoders => [qw(
                                   )
                                ],
               VLAN_decoders => [qw(
                                   )
                                ],
               PPP_decoders => [qw(
                                  )
                                ],
);

sub decodeIPOptions($) {
    my $optdata = $_[0];
    my $opthash;

    if ( length($optdata) gt 0 ) {
        my @bytes = unpack("C*", $optdata);
        my $bytepos = 0;
        my $optionlen = length($optdata);
        my $number;
        my $copy;
        my $class;
        my $name;
        my $length;
        my $data;

        while ( $bytepos < $optionlen ) {
            $number = ( @bytes[$bytepos] & 0x1F );
            $copy = ( @bytes[$bytepos] & 0x80 ) >> 7;
            $class = ( @bytes[$bytepos] & 0x60 ) >> 5;
            $name = $IP_OPT_MAP->{$number}->{'name'};
            if ( $IP_OPT_MAP->{$number}->{'length'} eq 0 ) {
                # Length is actual len for entire option
                $length = @bytes[$bytepos+1];
                debug("IP Option len is $length\n");
                if ( $length le 0 || $length gt ( $optionlen - $bytepos )) {
                    #something odd
                    $length = $optionlen - $bytepos;
                    $data = substr($optdata, $bytepos, $length);
                    $bytepos = $optionlen;
                    debug("IP Option len is $length\n");
                } else {
                    $data = substr($optdata, $bytepos, $length);
                    $bytepos = $length;
                }
            } elsif ( $IP_OPT_MAP->{$number}->{'length'} gt 0 ) {
                $data = substr($optdata, $bytepos, $IP_OPT_MAP->{$number}->{'length'});
                # length is fixed. skip the data we've got all we need
                $bytepos = $bytepos + $IP_OPT_MAP->{$number}->{'length'};
            } elsif ( exists $IP_OPT_MAP->{$number}->{'length'} ) {
                # there is no length or data. it just exists.
                $data = @bytes[$bytepos];;
                $length = 0;
            } else {
                # Treat it as an option with a length
                $length = @bytes[$bytepos+1];
                if ( $length le 0 || $length gt ( $optionlen - $bytepos ) ) {
                    # something odd
                    $length = $optionlen - $bytepos;
                    $data = substr($optdata, $bytepos, $length);
                    $bytepos = $optionlen;
                } else {
                    $data = substr($optdata, $bytepos, $length);
                    $bytepos = $length;
                }
            }
            $opthash->{$number}->{'name'} = $name;
            $opthash->{$number}->{'length'} = $length;
            $opthash->{$number}->{'copy'} = $copy;
            $opthash->{$number}->{'class'} = $class;
            $opthash->{$number}->{'data'} = $data;
            debug("IP Option len is $length\n");
        }
   }
   return $opthash;
}

sub decodeTCPOptions($) {
    my $optdata = $_[0];
    my $opthash;

    if ( length($optdata) gt 0 ) {
        my @bytes = unpack("C*", $optdata);
        my $bytepos = 0;
        my $optionlen = length($optdata);
        my $number;
        my $name;
        my $length;
        my $data;

        debug(sprintf("START TCPOPT Option Length is %d\n", $optionlen));
        while ( $bytepos < $optionlen ) {
            $number = @bytes[$bytepos];
        debug(sprintf("TCPOPT OPT Number is %d\n", $number));

            $name = exists $TCP_OPT_MAP->{$number}->{'name'}?$TCP_OPT_MAP->{$number}->{'name'}:"UNKNOWN";
        debug(sprintf("TCP OPT Name maps to %s\n", $name));
            if ( $TCP_OPT_MAP->{$number}->{'length'} eq 0 ) {
                # Length is actual len for entire option
                $length = @bytes[$bytepos+1];
                debug(sprintf("TCP OPT LEN eq 0 Read Length is %d\n", $length));
                if ( $length le 0 || $length gt ( $optionlen - $bytepos )) {
                    # something odd
                    $length = $optionlen - $bytepos;
                    debug(sprintf("TCPOPT len le 0 gt optlen is %d\n", $length));
                    $data = substr($optdata, $bytepos, $length);
                    $bytepos = $optionlen;
                } else {
                    $data = substr($optdata, $bytepos, $length);
                    $bytepos += $length;
                }
            } elsif ( $TCP_OPT_MAP->{$number}->{'length'} gt 0 ) {
                $data = substr($optdata, $bytepos, $TCP_OPT_MAP->{$number}->{'length'});
                # length is fixed. skip the data we've got all we need                
                $length = $TCP_OPT_MAP->{$number}->{'length'};
                debug(sprintf("TCP OPT LEN FIXED  Length is %d\n", $length));
                $bytepos += $length;
            } elsif ( exists $TCP_OPT_MAP->{$number}->{'length'} ) {
                # there is no length or data. it just exists.
                $data = @bytes[$bytepos];
                $length = 0;
                $bytepos += 1;
            } else {
                # Treat it as an option with a length
                $length = @bytes[$bytepos+1];
                debug(sprintf("TCP OPT LEN ELSE CONDITION Option Length is %d\n", $length));
                if ( $length le 0 || $length gt ( $optionlen - $bytepos ) ) {
                    # something odd
                    $length = $optionlen - $bytepos;
                    debug(sprintf("TCP OPT LEN ELSE len le 0 gt optlen Option Length is %d\n", $length));
                    $data = substr($optdata, $bytepos, $length);
                    $bytepos = $optionlen;
                } else {
                    $data = substr($optdata, $bytepos, $length);
                    $bytepos += $length;
                }
            }
            $opthash->{$number}->{'name'} = $name;
            $opthash->{$number}->{'length'} = $length;
            $opthash->{$number}->{'data'} = $data;
            debug(sprintf("TCPOPTLEN FINAL LEN Option Length is %d\n", $length));
        }
   }
   return $opthash;

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
                                                                                                                     1313,1        Bot
