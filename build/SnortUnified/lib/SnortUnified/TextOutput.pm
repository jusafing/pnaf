package SnortUnified::TextOutput;

#########################################################################################
#  $VERSION = "SnortUnified Parser - Copyright (c) 2007 Jason Brvenik";
# 
# A Perl module to make it easy to work with snort unified files.
# http://www.snort.org
# 
# This module handles all of the formatting and output methods for text based output
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

use Socket;
use NetPacket::Ethernet;
use NetPacket::IP qw(:ALL);
use NetPacket::TCP qw(:ALL);
use NetPacket::UDP qw(:ALL);
use NetPacket::ICMP qw(:ALL);
use SnortUnified::MetaData qw(:ALL);

my $class_self;

BEGIN {
   $class_self = __PACKAGE__;
   $VERSION = "1.5devel20070806";
}
my $LICENSE = "GNU GPL see http://www.gnu.org/licenses/gpl.txt for more information.";
sub Version() { "$class_self v$VERSION - Copyright (c) 2007 Jason Brvenik" };
sub License() { Version . "\nLicensed under the $LICENSE" };

@ISA = qw(Exporter);
@EXPORT = qw();
@EXPORT_OK = qw(
                format_packet_data
                print_packet_data
                print_alert
                format_alert
                print_log
                format_log
);

%EXPORT_TAGS = (
               ALL => [@EXPORT, @EXPORT_OK],
               packet_handlers => [qw(
                                       print_log
                                       format_log
                                       format_packet_data
                                       print_packet_data
                                     )
                              ],
               alert_handlers =>  [qw(
                                       print_alert
                                       format_alert
                                     )
                                  ],
);

sub print_packet_data($) {
    print format_packet_data($_[0]);
}   

sub format_packet_data($) {
    my $data = $_[0];
    my $buff = '';
    my $hex = '';
    my $ascii = '';
    my $len = length($data);
    my $count = 0;
    my $ret = "";

    for (my $i = 0;$i < length($data);$i += 16) {
       $buff = substr($data,$i,16);
       $hex = join(' ',unpack('H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2',$buff));
       $ascii = unpack('a16', $buff);
       $ascii =~ tr/A-Za-z0-9;:\"\'.,<>[]\\|?\/\`~!\@#$%^&*()_\-+={}/./c;
       $ret = $ret . sprintf("%.4X: %-50s%s\n", $count, $hex, $ascii);
       $count += length($buff);
    }
  return $ret;
}


sub print_alert($$$) {
    print format_alert($_[0], $_[1], $_[2]);
    print("------------------------------------------------------------------------\n");
}   

sub format_alert($$$) {
    my $rec = $_[0];
    my $sids = $_[1];
    my $class = $_[2];
    my $ret = "";

    my $time = gmtime($rec->{'tv_sec'});
    $ret = sprintf("%s {%s} %s:%d -> %s:%d\n" .
            "[**] [%d:%d:%d] %s [**]\n" .
            "[Classification: %s] [Priority: %d]\n", $time,
            $IP_PROTO_NAMES->{$rec->{'protocol'}},
            inet_ntoa(pack('N', $rec->{'sip'})),
            $rec->{'sp'}, inet_ntoa(pack('N', $rec->{'dip'})),
            $rec->{'dp'}, $rec->{'sig_gen'}, $rec->{'sig_id'},
            $rec->{'sig_rev'},
            get_msg($sids,$rec->{'sig_gen'},$rec->{'sig_id'},$rec->{'sig_rev'}),
            get_class($class,$rec->{'class'}),
            get_priority($class,$rec->{'class'},$rec->{'priority'}));

    foreach my $ref ($sids->{$rec->{'sig_gen'}}->{$rec->{'sig_id'}}->{'reference'}) {
        if ( defined $ref ) {
            $ret = $ret . sprintf("[Xref => %s]\n", $ref);
        } else {
            $ret = $ret . sprintf("[Xref => None]\n");
        }
    }
    return $ret;
}

sub print_log($$$) {
    print format_log($_[0], $_[1], $_[2]);
    print("=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n");
}


sub format_log($$$) {
    my $rec = $_[0];
    my $sids = $_[1];
    my $class = $_[2];
    my $eth_obj;
    my $ip_obj;
    my $tcp_obj;
    my $udp_obj;
    my $icmp_obj;
    my $time = gmtime($rec->{'pkt_sec'});
    my $ret = "";

    $ret = sprintf("[**] [%d:%d:%d] %s [**]\n[Classification: %s] [Priority: %d]\n",
            $rec->{'sig_gen'}, $rec->{'sig_id'}, $rec->{'sig_rev'},
            get_msg($sids,$rec->{'sig_gen'},$rec->{'sig_id'},$rec->{'sig_rev'}),
            get_class($class,$rec->{'class'}),
            get_priority($class,$rec->{'class'},$rec->{'priority'}));

    foreach my $ref ($sids->{$rec->{'sig_gen'}}->{$rec->{'sig_id'}}->{'reference'}) {
        if ( defined $ref ) {
            $ret = $ret . sprintf("[Xref => %s]\n", $ref);
        } else {
            $ret = $ret . sprintf("[Xref => None]\n");
        }
    }

    $ret = $ret . sprintf("Event ID: %lu     Event Reference: %lu\n",
            $rec->{'event_id'}, $rec->{'reference'});

    $eth_obj = NetPacket::Ethernet->decode($rec->{'pkt'});
    if ( $eth_obj->{type} eq $ETHERNET_TYPE_IP ) {
        $ip_obj = NetPacket::IP->decode($eth_obj->{data});
        if ( $ip_obj->{proto} ne IP_PROTO_TCP && $ip_obj->{proto} ne IP_PROTO_UDP ) {
            $ret = $ret . sprintf("%s %s -> %s", $time, $ip_obj->{src_ip}, $ip_obj->{dest_ip});
        } else {
            if ( $ip_obj->{proto} eq IP_PROTO_TCP ) {
                $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
                $ret = $ret . sprintf("%s %s:%d -> %s:%d\n",
                    $time,
                    $ip_obj->{src_ip},
                    $tcp_obj->{src_port},
                    $ip_obj->{dest_ip},
                    $tcp_obj->{dest_port});
            } elsif ( $ip_obj->{proto} eq IP_PROTO_UDP ) {
                $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
                $ret = $ret . sprintf("%s %s:%d -> %s:%d\n",
                $time,
                $ip_obj->{src_ip},
                $udp_obj->{src_port},
                $ip_obj->{dest_ip},
                $udp_obj->{dest_port});
            } else {
                # Should never get here
                print("DEBUGME: Why am I here - IP Header Print\n");
            }
        }
        $ret = $ret . sprintf("%s TTL:%d TOS:0x%X ID:%d IpLen:%d DgmLen:%d",
                $IP_PROTO_NAMES->{$ip_obj->{proto}},
                $ip_obj->{ttl},
                $ip_obj->{tos},
                $ip_obj->{id},
                $ip_obj->{len} - $ip_obj->{hlen},
                $ip_obj->{len});

        if ( $ip_obj->{flags} & $PKT_RB_FLAG ) {
            $ret = $ret . sprintf(" RB");
        }

        if ( $ip_obj->{flags} & $PKT_DF_FLAG ) {
            $ret = $ret . sprintf(" DF");
        }
        if ( $ip_obj->{flags} & $PKT_MF_FLAG ) {
            $ret = $ret . sprintf(" MF");
        }

        $ret = $ret . sprintf("\n");

        if ( length($ip_obj->{options}) gt 0 ) {
            my $IPOptions = decodeIPOptions($ip_obj->{options});
            foreach my $ipoptkey ( keys %{$IPOptions} ) {
                $ret = $ret . sprintf("IP Option %d : %s\n", $ipoptkey, $IPOptions->{'name'});
                $ret = $ret . format_packet_data($IPOptions->{'data'});
            }
        }

        if ( $ip_obj->{flags} & 0x00000001 ) {
            $ret = $ret . sprintf("Frag Offset: 0x%X   Frag Size: 0x%X",
                   $ip_obj->{foffset} & 0xFFFF, $ip_obj->{len});
        }

        if ( $ip_obj->{proto} eq IP_PROTO_TCP ) {
            $ret = $ret . sprintf("%s%s%s%s%s%s%s%s",
            $tcp_obj->{flags} & CWR?"1":"*",
            $tcp_obj->{flags} & ECE?"2":"*",
            $tcp_obj->{flags} & URG?"U":"*",
            $tcp_obj->{flags} & ACK?"A":"*",
            $tcp_obj->{flags} & PSH?"P":"*",
            $tcp_obj->{flags} & RST?"R":"*",
            $tcp_obj->{flags} & SYN?"S":"*",
            $tcp_obj->{flags} & FIN?"F":"*");
            $ret = $ret . sprintf(" Seq: 0x%lX  Ack: 0x%lX  Win: 0x%X  TcpLen: %d",
                   $tcp_obj->{seqnum},
                   $tcp_obj->{acknum},
                   $tcp_obj->{winsize},
                   length($tcp_obj->{data}));
            if ( defined $tcp_obj->{urg} && $tcp_obj->{urg} gt 0 ) {
                $ret = $ret . sprintf("  UrgPtr: 0x%X", $tcp_obj->{urg});
            }
            $ret = $ret . sprintf("\n");

            if ( length($tcp_obj->{options}) gt 0) {
                my $TCPOptions = decodeTCPOptions($tcp_obj->{options});
                foreach my $tcpoptkey ( keys %{$TCPOptions} ) {
                    $ret = $ret . sprintf("TCP Option %d : %s\n", $tcpoptkey, $TCPOptions->{$tcpoptkey}->{'name'});
                    $ret = $ret . format_packet_data($TCPOptions->{$tcpoptkey}->{'data'});
                }
            }
        } elsif ( $ip_obj->{proto} eq IP_PROTO_UDP ) {
            $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
            $ret = $ret . sprintf("Len: %d\n", $udp_obj->{len});
        } elsif ( $ip_obj->{proto} eq IP_PROTO_ICMP ) {
            $icmp_obj = NetPacket::ICMP->decode($ip_obj->{data});
            $ret = $ret . sprintf("Type:%d  Code:%d  %s\n", $icmp_obj->{type}, $icmp_obj->{code}, $ICMP_TYPES->{$icmp_obj->{type}});
        } else {
            # Should never get here
            print("DEBUGME: Why am I here - TCP/UDP/ICMP Header print\n");
        }
    } else {
        $ret = $ret . sprintf("Linktype %i not decoded.  Raw packet dumped\n",
                $eth_obj->{type});
        $ret = $ret . format_packet_data($eth_obj->{data});
    }

    return $ret;
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
