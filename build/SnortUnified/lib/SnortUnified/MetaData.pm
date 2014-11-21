package SnortUnified::MetaData;

#########################################################################################
#  $VERSION = "SnortUnified Parser - Copyright (c) 2007 Jason Brvenik";
# 
# A Perl module to make it easy to work with snort unified files.
# http://www.snort.org
# 
# Metadata handling routines
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
                 get_msg
                 get_snort_sids
                 print_snort_sids
                 get_class
                 get_class_name
                 get_class_type
                 get_snort_classifications
                 print_snort_classifications
                 get_priority
);

%EXPORT_TAGS = (
               ALL => [@EXPORT, @EXPORT_OK],
               sids => [qw(
                            get_snort_sids
                            print_snort_sids
                          )
                       ],
               classifications =>  [qw(
                                        get_class
                                        get_class_name
                                        get_class_type
                                        get_snort_classifications
                                        print_snort_classifications
                                      )
                                   ],
               priorities => [qw(
                                  get_priority
                                )
                             ],
               messages => [qw(
                                get_msg
                              )
                           ],
               ethernet_vars => [qw(
                                    $ETHERNET_TYPE_IP
                                    $ETHERNET_TYPE_ARP
                                    $ETHERNET_TYPE_REVARP
                                    $ETHERNET_TYPE_IPV6
                                    $ETHERNET_TYPE_IPX
                                    $ETHERNET_TYPE_PPPoE_DISC
                                    $ETHERNET_TYPE_PPPoE_SESS
                                    $ETHERNET_TYPE_8021Q
                                    $ETHERNET_TYPE_NAMES
                                   )
                                ],
                ip_vars => [qw($IP_PROTO_NAMES $IP_OPT_MAP)],
                tcp_vars => [qw($TCP_OPT_MAP)],
                icmp_vars => [qw($ICMP_TYPES)],
                pkt_flags => [qw($PKT_FRAG_FLAG $PKT_RB_FLAG $PKT_DF_FLAG $PKT_MF_FLAG)],

);

our $PKT_FRAG_FLAG = 0x00000001;
our $PKT_RB_FLAG   = 0x00000002;
our $PKT_DF_FLAG   = 0x00000004;
our $PKT_MF_FLAG   = 0x00000008;

our $ICMP_TYPES = {
    0 => 'Echo Reply',
    3 => 'Unreachable',
    4 => 'Source Quench',
    5 => 'Redirect',
    8 => 'Echo',
    9 => 'Router Advertisement',
    10 => 'Router Solicit',
    11 => 'Time Exceeded',
    12 => 'Parameter Problem',
    13 => 'Timestamp',
    14 => 'Timestamp Reply',
    15 => 'Information Request',
    16 => 'Information Reply',
    17 => 'Mask Request',
    18 => 'Mask Reply',
};

our $TCP_OPT_MAP = {
     0  => { 'length' => 1,
             'name'   => 'End of Option List',
           },
     1  => { 'length' => 1,
             'name'   => 'No-Operation',
           },
     2  => { 'length' => 4,
             'name'   => 'Maximum Segment Size',
           },
     3  => { 'length' => 3,
             'name'   => 'WSOPT - Window Scale',
           },
     4  => { 'length' => 2,
             'name'   => 'SACK Permitted',
           },
     5  => { 'length' => 0,
             'name'   => 'SACK',
           },
     6  => { 'length' => 6,
             'name'   => 'Echo (obsolete)',
           },
     7  => { 'length' => 6,
             'name'   => 'Echo Reply (obsolete)',
           },
     8  => { 'length' => 10,
             'name'   => 'TSOPT - Time Stamp Option',
           },
     9  => { 'length' => 2,
             'name'   => 'Partial Order Connection Permitted',
           },
     10 => { 'length' => 3,
             'name'   => 'Partial Order Service Profile',
           },
     11 => { 'length' => 6,
             'name'   => 'CC, Connection Count',
           },
     12 => { 'length' => 6,
             'name'   => 'CC.NEW',
           },
     13 => { 'length' => 6,
             'name'   => 'CC.ECHO',
           },
     14 => { 'length' => 3,
             'name'   => 'TCP Alternate Checksum Request',
           },
     15 => { 'length' => 0,
             'name'   => 'TCP Alternate Checksum Data',
           },
     16 => { 'length' => undef,
             'name'   => 'Skeeter',
           },
     17 => { 'length' => undef,
             'name'   => 'Bubba',
           },
     18 => { 'length' => 3,
             'name'   => 'Trailer Checksum Option',
           },
     19 => { 'length' => 18,
             'name'   => 'MD5 Signature Option',
           },
     20 => { 'length' => undef,
             'name'   => 'SCPS Capabilities',
           },
     21 => { 'length' => undef,
             'name'   => 'Selective Negative Acknowledgements',
           },
     22 => { 'length' => undef,
             'name'   => 'Record Boundaries',
           },
     23 => { 'length' => undef,
             'name'   => 'Corruption experienced',
           },
     24 => { 'length' => undef,
             'name'   => 'SNAP',
           },
     25 => { 'length' => undef,
             'name'   => 'Unassigned',
           },
     26 => { 'length' => undef,
             'name'   => 'TCP Compression Filter',
           },
     253 => { 'length' => 0,
              'name'   => 'RFC3692-style Experiment 1',
            },
     254 => { 'length' => 0,
              'name'   => 'RFC3692-style Experiment 2',
            },
};


our $IP_PROTO_NAMES = {
    4 => 'IP',
    1 => 'ICMP',
    2 => 'IGMP',
    94 => 'IPIP',
    6 => 'TCP',
    17 => 'UDP',,
};

our $IP_OPT_MAP = {
     0  =>  { 'name'   => 'End of options list',
              'length' => 1,
            },
     1  =>  { 'name'   => 'NOP',
              'length' => 1,
            },
     2  =>  { 'name'   => 'Security',
              'length' => 11,
            },
     3  =>  { 'name'   => 'Loose Source Route',
              'length' => 0,
            },
     4  =>  { 'name'   => 'Time stamp',
              'length' => 0,
            },
     5  =>  { 'name'   => 'Extended Security',
              'length' => 0,
            },
     6  =>  { 'name'   => 'Commercial Security',
              'length' => undef,
            },
     7  =>  { 'name'   => 'Record Route',
              'length' => 0,
            },
     8  =>  { 'name'   => 'Stream Identifier',
              'length' => 4,
            },
     9  =>  { 'name'   => 'Strict Source Route',
              'length' => 0,
            },
     10 =>  { 'name'   => 'Experimental Measurement',
              'length' => undef,
            },
     11 =>  { 'name'   => 'MTU Probe',
              'length' => 4,
            },
     12 =>  { 'name'   => 'MTU Reply',
              'length' => 4,
            },
     13 =>  { 'name'   => 'Experimental Flow Control',
              'length' => undef,
            },
     14 =>  { 'name'   => 'Expermental Access Control',
              'length' => undef,
            },
     15 =>  { 'name'   => '15',
              'length' => undef,
            },
     16 =>  { 'name'   => 'IMI Traffic Descriptor',
              'length' => undef,
            },
     17 =>  { 'name'   => 'Extended Internet Proto',
              'length' => undef,
            },
     18 =>  { 'name'   => 'Traceroute',
              'length' => 12,
            },
     19 =>  { 'name'   => 'Address Extension',
              'length' => 10,
            },
     20 =>  { 'name'   => 'Router Alert',
              'length' => 4,
            },
     21 =>  { 'name'   => 'Selective Directed Broadcast Mode',
              'length' => 0,
            },
     22 =>  { 'name'   => 'NSAP Addresses',
              'length' => undef,
            },
     23 =>  { 'name'   => 'Dynamic Packet State',
              'length' => undef,
            },
     24 =>  { 'name'   => 'Upstream Multicast Packet',
              'length' => undef,
            },
     25 =>  { 'name'   => '25',
              'length' => undef,
            },
     26 =>  { 'name'   => '26',
              'length' => undef,
            },
     27 =>  { 'name'   => '27',
              'length' => undef,
            },
     28 =>  { 'name'   => '28',
              'length' => undef,
            },
     29 =>  { 'name'   => '29',
              'length' => undef,
            },
     30 =>  { 'name'   => '30',
              'length' => undef,
            },
     31 =>  { 'name'   => '30',
              'length' => undef,
            },
};

our $ETHERNET_TYPE_IP = 0x0800;
our $ETHERNET_TYPE_ARP = 0x0806;
our $ETHERNET_TYPE_REVARP = 0x8035;
our $ETHERNET_TYPE_IPV6 = 0x86dd;
our $ETHERNET_TYPE_IPX = 0x8137;
our $ETHERNET_TYPE_PPPoE_DISC = 0x8863;
our $ETHERNET_TYPE_PPPoE_SESS = 0x8864;
our $ETHERNET_TYPE_8021Q = 0x8100;

our $ETHERNET_TYPE_NAMES = {
    0x0800 => 'IP',
    0x0806 => 'ARP',
    0x809B => 'APPLETALK',
    0x814C => 'SNMP',
    0x86DD => 'IPv6',
    0x880B => 'PPP',
};

sub get_msg($$$$) {
    my $sids = $_[0];
    my $gen = $_[1];
    my $id = $_[2];
    my $rev = $_[3];

    if ( defined $sids->{$gen}->{$id}->{'msg'} ) {
        if ( defined $sids->{$gen}->{$id}->{$rev}->{'msg'} ) {
            return $sids->{$gen}->{$id}->{$rev}->{'msg'};
        } else {
            return $sids->{$gen}->{$id}->{'msg'};
        }
    } else {
        return "RULE MESSAGE UNKNOWN";
    }
}

sub get_snort_sids($$) {
    my $sidfile = $_[0];
    my $genfile = $_[1];
    my @sid;
    my $sids;
    my @generator;

    return undef unless open(FD, "<", $sidfile);
    while (<FD>) {
        s/#.*//;
        next if /^(\s)*$/;
        chomp;
        @sid = split(/\s\|\|\s/);
        $sids->{1}->{$sid[0]}->{'msg'} = $sid[1];
        $sids->{1}->{$sid[0]}->{'reference'} = $sid[2..$#sid];
    }
    close(FD);

    return $sids unless open(FD, "<", $genfile);
    while (<FD>) {
        s/#.*//;
        next if /^(\s)*$/;
        chomp;
        @generator = split(/\s\|\|\s/);
        $sids->{$generator[0]}->{$generator[1]}->{'msg'} = $generator[2];
    }
    return $sids;
}

sub print_snort_sids($) {
    my $sids = $_[0];

    foreach my $gen (keys %{$sids}) {
      foreach my $sid (keys %{$sids->{$gen}}) {
        print("$gen:$sid || " . get_msg($sids,$gen,$sid,0) );
        foreach my $ref ($sids->{$gen}->{$sid}->{'reference'}) {
            print(" || $ref") if defined $ref;
        }
      print("\n");
      }
    }
}

sub get_class($$) {
    my $class = $_[0];
    my $classid = $_[1];

    return get_class_type($class,$classid);

}

sub get_class_name($$) {
    my $class = $_[0];
    my $classid = $_[1];

    if ( defined $class->{$classid}->{'name'} ) {
        return $class->{$classid}->{'name'};
    } else {
        return "unknown";
    }
}

sub get_class_type($$) {
    my $class = $_[0];
    my $classid = $_[1];

    if ( defined $class->{$classid}->{'type'} ) {
        return $class->{$classid}->{'type'};
    } else {
        return "unknown";
    }
}


sub get_snort_classifications ($) {
    my $file = $_[0];
    my @classification;
    my $class;
    my $classid = 1;

    return undef unless open(FD, "<", $file);
    while (<FD>) {
        s/#.*//;
        s/: /:/;
        next if /^(\s)*$/;
        chomp;
        @classification = split(/:/);
        @classification = split(/,/,$classification[1]);
        $class->{$classid}->{'type'} = $classification[0];
        $class->{$classid}->{'name'} = $classification[1];
        $class->{$classid}->{'priority'} = $classification[2];
        $classid++;
    }
    close(FD);

    return $class;
}

sub print_snort_classifications($) {
    my $class = $_[0];

    foreach my $key (keys %{$class}) {
       print("Classification ID       : $key\n");
       print("Classification TYPE     : $class->{$key}->{'type'}\n");
       print("Classification NAME     : $class->{$key}->{'name'}\n");
       print("Classification PRIORITY : $class->{$key}->{'priority'}\n");
       print("\n");
    }
}

sub get_priority($$$) {
    my $class = $_[0];
    my $classid = $_[1];
    my $pri = $_[2];

    if ( $pri gt 0 ) {
        return $pri;
    } else {
        if ( $class->{$classid}->{'priority'} gt 0 ) {
            return $class->{$classid}->{'priority'};
        } else {
            return 0;
        }
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
