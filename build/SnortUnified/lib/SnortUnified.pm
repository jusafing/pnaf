package SnortUnified;

#########################################################################################
#  $VERSION = "SnortUnified Parser - Copyright (c) 2007 Jason Brvenik";
# 
# A Perl module to make it east to work with snort unified files.
# http://www.snort.org
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
# Changes:
# V1.1 - Brvenik - Make it speedy
#########################################################################################
# TODO: in no specific order
#  - Documentation
#  - Print alerts like barnyard does
#  - Print logs like barnyard does
#  - CSV output
#  - XML output
#  - MYSQL output
#  - fuzzy find next valid record for corrupt unifieds
#  - Decode protocols
# 
#########################################################################################
# NOTES:
#########################################################################################

use strict;
use warnings;
require Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

use Carp  qw(cluck);
use Socket;
use Fcntl qw(:flock);
use SnortUnified::Handlers qw(:ALL);

# XXX - JRB - Move all of this functionality to Net::Packet, it is maintained
# use NetPacket::Ethernet;
# use NetPacket::IP qw(:ALL);
# use NetPacket::TCP qw(:ALL);
# use NetPacket::UDP qw(:ALL);
# use NetPacket::ICMP qw(:ALL);

my $class_self;

BEGIN {
   $class_self = __PACKAGE__;
   $VERSION = "1.620110126";
}
my $LICENSE = "GNU GPL see http://www.gnu.org/licenses/gpl.txt for more information.";
sub Version() { "$class_self v$VERSION - Copyright (c) 2007 Jason Brvenik" };
sub License() { Version . "\nLicensed under the $LICENSE" };

# Pollute global namespace
@ISA = qw(Exporter);
@EXPORT = qw(
                Version
                License
                debug
                $debug
);

@EXPORT_OK = qw(
                 $LOGMAGIC
                 $ALERTMAGIC
                 $UF_Record
                 $alert_fields
                 $log_fields
                 $alert2_fields
                 $log2_fields
                 $extra_data_fields
                 $flock_mode
                 $LOGMAGIC
                 $ALERTMAGIC
                 $UF
                 closeSnortUnified
                 openSnortUnified
                 readSnortUnifiedRecord
                 readSnortUnified2Record
                 $UNIFIED2_EVENT
                 $UNIFIED2_PACKET
                 $UNIFIED2_IDS_EVENT
                 $UNIFIED2_EVENT_EXTENDED
                 $UNIFIED2_PERFORMANCE
                 $UNIFIED2_PORTSCAN
                 $UNIFIED2_IDS_EVENT_IPV6
                 $UNIFIED_LOG
                 $UNIFIED_ALERT
                 $UNIFIED2
                 $UNIFIED2_TYPES
                 $UNIFIED2_EXTRA_DATA
             );

%EXPORT_TAGS = (
               ALL => [@EXPORT, @EXPORT_OK],
               magic_vars => [qw(
                                  $LOGMAGIC 
                                  $ALERTMAGIC
                                )
                             ],
               record_vars => [qw(
                                   $UF_Record 
                                   $alert_fields 
                                   $log_fields
                                   $alert2_fields 
                                   $log2_fields
                                 )
                               ],
               pkt_flags => [qw(
                                 $PKT_FRAG_FLAG 
                                 $PKT_RB_FLAG 
                                 $PKT_DF_FLAG 
                                 $PKT_MF_FLAG
                               )
                            ],
               record_types => [qw(
                                    $UNIFIED2_EVENT
                                    $UNIFIED2_PACKET
                                    $UNIFIED2_IDS_EVENT
                                    $UNIFIED2_EVENT_EXTENDED
                                    $UNIFIED2_PERFORMANCE
                                    $UNIFIED2_PORTSCAN
                                    $UNIFIED2_IDS_EVENT_IPV6
                                    $UNIFIED2_TYPES
                                    $UNIFIED2_EXTRA_DATA
                                  )
                                ],
               unified_types => [qw(
                                    $UNIFIED_LOG
                                    $UNIFIED_ALERT
                                    $UNIFIED2
                                   )
                                ],
);

# > 0 == turn on debugging
our $debug = 0;
# > 0 == use flock
our $flock_mode = 0;

our $LOGMAGIC = 0xdead1080;
our $ALERTMAGIC = 0xdead4137;
my $LOGMAGICV = 0xdead1080;
my $LOGMAGICN = 0x8010adde;;
my $ALERTMAGICV = 0xdead4137;
my $ALERTMAGICN = 0x3741adde;

our $UNIFIED_LOG   = "LOG";
our $UNIFIED_ALERT = "ALERT";
our $UNIFIED2      = "UNIFIED2";

our $UNIFIED2_EVENT                = 1;
our $UNIFIED2_PACKET               = 2;
our $UNIFIED2_IDS_EVENT            = 7;
our $UNIFIED2_EVENT_EXTENDED       = 66;
our $UNIFIED2_PERFORMANCE          = 67;
our $UNIFIED2_PORTSCAN             = 68;
our $UNIFIED2_IDS_EVENT_IPV6       = 72;
our $UNIFIED2_IDS_EVENT_MPLS       = 99;
our $UNIFIED2_IDS_EVENT_IPV6_MPLS  = 100;
our $UNIFIED2_IDS_EVENT_VLAN       = 104;
our $UNIFIED2_IDS_EVENT_IPV6_VLAN  = 105;
our $UNIFIED2_EXTRA_DATA           = 110;

our $UNIFIED2_TYPES = {
        $UNIFIED2_EVENT                => 'EVENT',
        $UNIFIED2_PACKET               => 'PACKET',
        $UNIFIED2_IDS_EVENT            => 'IPV4 EVENT',
        $UNIFIED2_EVENT_EXTENDED       => 'EXTENDED',
        $UNIFIED2_PERFORMANCE          => 'PERFORMANCE',
        $UNIFIED2_PORTSCAN             => 'PORTSCAN',
        $UNIFIED2_IDS_EVENT_IPV6       => 'IPV6 EVENT',
        $UNIFIED2_IDS_EVENT_MPLS       => 'MPLS EVENT',
        $UNIFIED2_IDS_EVENT_IPV6_MPLS  => 'IPV6 MPLS EVENT',
        $UNIFIED2_IDS_EVENT_VLAN       => 'VLAN EVENT',
        $UNIFIED2_IDS_EVENT_IPV6_VLAN  => 'IPV6 VLAN EVENT',
        $UNIFIED2_EXTRA_DATA           => 'EXTRA DATA',

};

my $unified2_type_masks = {
        $UNIFIED2_EVENT          => 'N11n2c2',
        $UNIFIED2_PACKET         => 'N7',
        $UNIFIED2_IDS_EVENT      => 'N11n2c2',
        $UNIFIED2_EVENT_EXTENDED => '',
        $UNIFIED2_PERFORMANCE    => '',
        $UNIFIED2_PORTSCAN       => '',
        # Patch from Martin Schütte - info...at...mschuette.name
        $UNIFIED2_IDS_EVENT_IPV6 => 'N9N4N4n2c2',
        # Support 104 and 105 - sfutil/Unified2_common.h
        $UNIFIED2_IDS_EVENT_VLAN       => 'N11n2c4Nn2',
        $UNIFIED2_IDS_EVENT_IPV6_VLAN  => 'N9N4N4n2c4Nn2',
        # "sfutil/Unified2_common.h" line 142
        # This is a variable length record, like a packet record
        # Last field is the length of the record inclusive of header
        # Within the header is a type dsignation that needs handling
        # "sfutil/Unified2_common.h" line 145
        #     EVENT_INFO_XFF_IPV4 = 1,
        #     EVENT_INFO_XFF_IPV6 ,
        #     EVENT_INFO_REVIEWED_BY,
        #     EVENT_INFO_GZIP_DATA
        # /* Length of the data + sizeof(blob_length) + sizeof(data_type)*/
        # ... blah blah blah you end up with N9 after it all stacks up
        $UNIFIED2_EXTRA_DATA           => 'N9',

};

our $U2_PACKET_FLAG          = 1;
our $U2_FLAG_BLOCKED         = 0x20;

our $UF = { 
        'FILENAME' => '',
        'TYPE' => '',
        'MAGIC' => '',
        'VERSION_MAJOR' => '',
        'VERSION_MINOR' => '',
        'TIMEZONE' => '',
        'SIG_FLAG' => '',
        'SNAPLEN' => '',
        'LINKTYPE' => '',
        'PACKSTR' => '',
        'FIELDS' => '',
        'RECORDSIZE' => 0,
        'FILESIZE' => 0,
        'FILEMTIME' => 0,
        'FILEPOS' => 0,
        'PATIENCE' => 1,
        'TOLERANCE' => 3,
        'LOCKED' => 0,
        '64BIT' => 0,
};

our $UF_Record = {};

# set up record structure
my $alert32_fields = [
        'sig_gen',
        'sig_id',
        'sig_rev',
        'class',
        'pri',
        'event_id',
        'reference',
        'tv_sec',
        'tv_usec',
        'tv_sec2',
        'tv_usec2',
        'sip',
        'dip',
        'sp',
        'dp',
        'protocol',
        'flags'
];

my $unified2_ids_fields = [
        'sensor_id',
        'event_id',
        'tv_sec',
        'tv_usec',
        'sig_id',
        'sig_gen',
        'sig_rev',
        'class',
        'pri',
        'sip',
        'dip',
        'sp',
        'dp',
        'protocol',
        'pkt_action'
];

our $alert2_fields = $unified2_ids_fields;

my $unified2_packet_fields = [
        'sensor_id',
        'event_id',
        'tv_sec',
        'pkt_sec',
        'pkt_usec',
        'linktype',
        'pkt_len',
        'pkt'
];

our $log2_fields = $unified2_packet_fields;

my $unified2_header = [
        'type',
        'length',
];

my $alert64_fields = [
        'sig_gen',
        'sig_id',
        'sig_rev',
        'class',
        'pri',
        'event_id',
        'reference',
        'p1',
        'tv_sec',
        'p1a',
        'tv_usec',
        'p1b',
        'p2',
        'tv_sec2',
        'p2a',
        'tv_usec2',
        'p2b',
        'sip',
        'dip',
        'sp',
        'dp',
        'protocol',
        'flags'
];

our $alert_fields = $alert32_fields;

my $log32_fields = [
        'sig_gen',
        'sig_id',
        'sig_rev',
        'class',
        'pri',
        'event_id',
        'reference',
        'tv_sec',
        'tv_usec',
        'flags',
        'pkt_sec',
        'pkt_usec',
        'caplen',
        'pktlen',
        'pkt',
];

my $log64_fields = [
        'sig_gen',
        'sig_id',
        'sig_rev',
        'class',
        'pri',
        'event_id',
        'reference',
        'p1',
        'tv_sec',
        'p1a',
        'tv_usec',
        'p1b',
        'flags',
        'p2',
        'pkt_sec',
        'p2a',
        'pkt_usec',
        'p2b',
        'caplen',
        'pktlen',
        'pkt',
];

our $log_fields = $log32_fields;

# set up the new IDS events - type 104
# sfutil/Unified2_common.h
my $vlan_alert_fields32 = [
    'sensor_id',
    'event_id',
    'event_second',
    'event_microsecond',
    'signature_id',
    'generator_id',
    'signature_revision',
    'classification_id',
    'priority_id',
    'ip_source',
    'ip_destination',
    'sport_itype',
    'dport_icode',
    'protocol',
    'impact_flag', # //overloads packet_action
    'impact',
    'blocked',
    'mpls_label',
    'vlanId',
    # 'pad2', # Policy ID
    'policyID',
];

our $vlan_alerts = $vlan_alert_fields32;

# type 105
my $vlan_alert_fields64 = [
    'sensor_id',
    'event_id',
    'event_second',
    'event_microsecond',
    'signature_id',
    'generator_id',
    'signature_revision',
    'classification_id',
    'priority_id',
    'in6_addr ip_source',
    'in6_addr ip_destination',
    'sport_itype',
    'dport_icode',
    'protocol',
    'impact_flag',
    'impact',
    'blocked',
    'mpls_label',
    'vlanId',
    'pad2', # /*could be IPS Policy local id to support local sensor alerts*/
];

# data_blob could contain any of the types, implementing generic handling for now
# you will need to register a handler for how _you_ want to handle the data 
# I'm providing an example for XFF

my $unified2_extra_data_fields = [
    'event_type',
    'event_length',
    'sensor_id',
    'event_id',
    'tv_sec',
    'type',
    'datatype',
    'bloblength',
    'data_blob',
];

our $extra_data_fields = $unified2_extra_data_fields;

###############################################################
# Close the unified file
###############################################################
sub closeSnortUnified() {
    if ( $UF->{'LOCKED'} ) {
        flock(UFD, LOCK_UN);
    }
    close(UFD);
}

###############################################################
# Open a Snort unified file and return a hash 
# describing the file or undef if we don;t handle it.
# die if we cannot open the file.
###############################################################
sub openSnortUnified($) {
   $UF->{'FILENAME'} = $_[0];
   $UF->{'TYPE'} = '';
   $UF->{'PACKSTR'} = '';
   $UF->{'FIELDS'} = '';
   $UF->{'RECORDSIZE'} = 0;
   $UF->{'FILESIZE'} = 0;
   $UF->{'FILEMTIME'} = 0;
   $UF->{'FILEPOS'} = 0;


   my $magic = 0;
   if ( !open(UFD, "<", $UF->{'FILENAME'})) {
     cluck("Cannot open file $UF->{'FILENAME'}\n");
     $UF = undef;
     return $UF;
   }

   binmode(UFD);
   # See if we can get an exclusive lock
   # The presumption being that if we can get an exclusive
   # then the file is not actively being written to
   # JRB - This turns out to not be true :(
   # Only real alternative option is to keep reading the file
   # and occasionally check for a newer file to process
   if ( $flock_mode ) {
       if ( flock(UFD, LOCK_EX & LOCK_NB) ) {
           debug("Got an exclusive lock\n");
           $UF->{'LOCKED'} = 1;
       } else {
           $UF->{'LOCKED'} = 0;
           debug("Did not get an exclusive lock\n");
       }
   }

   (undef,undef,undef,undef,undef,undef,undef,$UF->{'FILESIZE'},undef,$UF->{'FILEMTIME'},undef,undef,undef) = stat(UFD);
   $UF->{'FILESIZE'} = (stat(UFD))[7];
   $UF->{'FILEMTIME'} = (stat(UFD))[9];

   read(UFD, $magic, 4);
   $magic = unpack('V', $magic);

  if ( $UF->{'64BIT'} ) {
     debug("Handling unified file with 64bit timevals");
     $log_fields = $log64_fields;
     $alert_fields = $alert64_fields;
     if ( $magic eq $LOGMAGICV ) {
       $UF->{'TYPE'} = $UNIFIED_LOG;
       $UF->{'FIELDS'} = $log_fields;
       $UF->{'RECORDSIZE'} = 20 * 4;
       $UF->{'PACKSTR'} = 'V20';

     } elsif ( $magic eq $LOGMAGICN ) {
       $UF->{'TYPE'} = $UNIFIED_LOG;
       $UF->{'FIELDS'} = $log_fields;
       $UF->{'RECORDSIZE'} = 20 * 4;
       $UF->{'PACKSTR'} = 'N20';

     } elsif ( $magic eq $ALERTMAGICV ) {
       $UF->{'TYPE'} = $UNIFIED_ALERT;
       $UF->{'FIELDS'} = $alert_fields;
       $UF->{'RECORDSIZE'} = (21 * 4) + (2 * 2);
       $UF->{'PACKSTR'} = 'V19v2V2';

     } elsif ( $magic eq $ALERTMAGICN ) {
       $UF->{'TYPE'} = $UNIFIED_ALERT;
       $UF->{'FIELDS'} = $alert_fields;
       $UF->{'RECORDSIZE'} = (21 * 4) + (2 * 2);
       $UF->{'PACKSTR'} = 'N19n2N2';

     } else {
       # no magic, go back to beginning
       seek(UFD,0,0);
       $UF->{'TYPE'} = $UNIFIED2;
       # The rest doesn't really matter because it changes from record to record
       debug("No match on magic, assuming unified2");
     }
  } else { # assume 32bit
     debug("Handling unified file with 32bit timevals");
     $log_fields = $log32_fields;
     $alert_fields = $alert32_fields;
     if ( $magic eq $LOGMAGICV ) {
       $UF->{'TYPE'} = 'LOG';
       $UF->{'FIELDS'} = $log_fields;
       $UF->{'RECORDSIZE'} = 14 * 4;
       $UF->{'PACKSTR'} = 'V14';

     } elsif ( $magic eq $LOGMAGICN ) {
       $UF->{'TYPE'} = 'LOG';
       $UF->{'FIELDS'} = $log_fields;
       $UF->{'RECORDSIZE'} = 14 * 4;
       $UF->{'PACKSTR'} = 'N14';

     } elsif ( $magic eq $ALERTMAGICV ) {
       $UF->{'TYPE'} = 'ALERT';
       $UF->{'FIELDS'} = $alert_fields;
       $UF->{'RECORDSIZE'} = (15 * 4) + (2 * 2);
       $UF->{'PACKSTR'} = 'V13v2V2';

     } elsif ( $magic eq $ALERTMAGICN ) {
       $UF->{'TYPE'} = 'ALERT';
       $UF->{'FIELDS'} = $alert_fields;
       $UF->{'RECORDSIZE'} = (15 * 4) + (2 * 2);
       $UF->{'PACKSTR'} = 'N13n2N2';

     } else {
       # no magic, go back to beginning
       seek(UFD,0,0);
       $UF->{'TYPE'} = $UNIFIED2;
       # Note the new fields
       $log_fields = $unified2_packet_fields;
       $alert_fields = $unified2_ids_fields;
       # The rest doesn't really matter because it changes from record to record
       debug("No match on magic, assuming unified2");
     }
  }
  
  exec_handler("unified_opened", $UF);

  readSnortUnifiedHeader($UF);

  return $UF;
}


###############################################################
# Read a record from the unified2 file and return it
# undef if we read 0 from file and cluck and return undef
# if we are not working with a unified2 file
# return -1 if we have failed to pass registered qualifiers
# otherwise return $HASH containing the record
# JRB - This whole bit needs to be redone, it has outlived
# the quick usecase and is simply ugly
###############################################################
sub readSnortUnified2Record() {
    my @record = undef;
    if ( $UF->{'TYPE'} ne $UNIFIED2 ) {
        cluck("readSnortUnified2Record does not handle " . $UF->{'TYPE'} . " files");
        return undef;
    } else {
        debug("Handling $UF->{'TYPE'} file");
    }

    my $buffer = '';
    my $readsize = 0;
    my $pktsize = 0;
    my $size = 0;
    my $mtime = 0;
    my $fsize;
    my @fields;
    my $i=0;

    $UF_Record = undef;
    $UF->{'FILESIZE'} = (stat(UFD))[7];
    $UF->{'FILEMTIME'} = (stat(UFD))[9];

    # read in the header (type,length)
    ($size, $buffer) = readData(8, $UF->{'TOLERANCE'});
    if ( $size <= 0 ) { 
        return undef;
    }
    
    ($UF_Record->{'TYPE'},$UF_Record->{'SIZE'}) = unpack("NN", $buffer);

    debug("Header type is " . $UF_Record->{'TYPE'} . " with size of " . $UF_Record->{'SIZE'});

    ($size, $buffer) = readData($UF_Record->{'SIZE'}, $UF->{'TOLERANCE'});

    if ($size <= 0) {
        return undef;
    }

    debug("Read a record of $size bytes");
    debug("Handling type " . $UF_Record->{'TYPE'});

    if ( $UF_Record->{'TYPE'} eq $UNIFIED2_PACKET ) {
        debug("Handling a packet record from the unified2 file");
        $UF_Record->{'FIELDS'} = $log2_fields;
        debug("Unpacking with mask " , $unified2_type_masks->{$UNIFIED2_PACKET});
        @record = unpack($unified2_type_masks->{$UNIFIED2_PACKET}, $buffer);
        foreach my $fld (@{$UF_Record->{'FIELDS'}}) {
            if ($fld ne 'pkt') {
                $UF_Record->{$fld} = $record[$i++];
                debug("Field " . $fld . " is set to " . $UF_Record->{$fld});
            } else {
                debug("Filling in pkt with " . $UF_Record->{'pkt_len'} . " bytes");
                $UF_Record->{'pkt'} = substr($buffer, $UF_Record->{'pkt_len'} * -1, $UF_Record->{'pkt_len'});
            }
        }
        exec_handler("unified2_packet", $UF_Record);

    } elsif ($UF_Record->{'TYPE'} eq $UNIFIED2_IDS_EVENT) {
        debug("Handling an IDS event from the unified2 file");
        $UF_Record->{'FIELDS'} = $alert2_fields;
        debug("Unpacking with mask " . $unified2_type_masks->{$UNIFIED2_IDS_EVENT});
        @record = unpack($unified2_type_masks->{$UNIFIED2_IDS_EVENT}, $buffer);
        foreach my $fld (@{$UF_Record->{'FIELDS'}}) {
            $UF_Record->{$fld} = $record[$i++];
            debug("Field " . $fld . " is set to " . $UF_Record->{$fld});
        }
        exec_handler("unified2_event", $UF_Record);

    } elsif ($UF_Record->{'TYPE'} eq $UNIFIED2_IDS_EVENT_IPV6) {  # added, ms
        debug("Handling an IDS IPv6 event from the unified2 file");
        $UF_Record->{'FIELDS'} = $alert2_fields;
        debug("Unpacking with mask " .  $unified2_type_masks->{$UNIFIED2_IDS_EVENT_IPV6});
        @record = unpack($unified2_type_masks->{$UNIFIED2_IDS_EVENT_IPV6}, $buffer);

        # N9 - first 9 uint32 fields:
        foreach my $fld (@{$UF_Record->{'FIELDS'}}[0 .. 8]) {
            $UF_Record->{$fld} = $record[$i++];
            debug("Field " . $fld . " is set to " . $UF_Record->{$fld});
        }
        # XXX JRB - need to look here at the "right" way to do it, all addresses are thus far represented as numbers
        # XXX JRB - and this is a deviation from that. Given that Socket6 ans INET6 are not yet part of CORE
        # XXX JRB - I'm inclined to leave it as is until someone complains - look at Net::INET6Glue or AnyEvent 
        # XXX JRB - as easy methods but I'm guessing perl6 is out before perl5 ipv6 support is stable 
        # N4N4 - the IPv6 addrs:
        foreach my $fld (@{$UF_Record->{'FIELDS'}}[9 .. 10]) {
			my @unp_tmp = unpack('n8', pack('N4', $record[$i .. $i+3]));
           $UF_Record->{$fld} = sprintf('%x:%x:%x:%x:%x:%x:%x:%x', @unp_tmp);
            $i += 4;
            debug("Field " . $fld . " is set to " . $UF_Record->{$fld});
        }
        # n2c2 - last fields:
        foreach my $fld (@{$UF_Record->{'FIELDS'}}[11 .. 14]) {
            $UF_Record->{$fld} = $record[$i++];
            debug("Field " . $fld . " is set to " . $UF_Record->{$fld});
        }
        exec_handler("unified2_event", $UF_Record);
    } elsif ($UF_Record->{'TYPE'} eq $UNIFIED2_IDS_EVENT_VLAN ) {
        debug("Handling a type $UNIFIED2_IDS_EVENT_VLAN IDS event from the unified2 file");
        $UF_Record->{'FIELDS'} = $vlan_alert_fields32;
        debug("Unpacking with mask " . $unified2_type_masks->{$UNIFIED2_IDS_EVENT_VLAN});
        @record = unpack($unified2_type_masks->{$UNIFIED2_IDS_EVENT_VLAN}, $buffer);
        foreach my $fld (@{$UF_Record->{'FIELDS'}}) {
            $UF_Record->{$fld} = $record[$i++];
            debug("Field " . $fld . " is set to " . $UF_Record->{$fld});
        }
        exec_handler("unified2_event", $UF_Record);

    } elsif ($UF_Record->{'TYPE'} eq $UNIFIED2_IDS_EVENT_IPV6_VLAN ) {
        debug("Handling a type $UNIFIED2_IDS_EVENT_VLAN IDS event from the unified2 file");
        $UF_Record->{'FIELDS'} = $vlan_alert_fields64;
        debug("Unpacking with mask " . $unified2_type_masks->{$UNIFIED2_IDS_EVENT_IPV6_VLAN});
        @record = unpack($unified2_type_masks->{$UNIFIED2_IDS_EVENT_IPV6_VLAN}, $buffer);
        foreach my $fld (@{$UF_Record->{'FIELDS'}}) {
            $UF_Record->{$fld} = $record[$i++];
            debug("Field " . $fld . " is set to " . $UF_Record->{$fld});
        }
        exec_handler("unified2_event", $UF_Record);
    
    } elsif ($UF_Record->{'TYPE'} eq $UNIFIED2_EXTRA_DATA) {
       debug("Handling a type $UNIFIED2_EXTRA_DATA (EXTRA DATA) record from the unified2 file");
       $UF_Record->{'FIELDS'} = $extra_data_fields;
       debug("Unpacking with mask " , $unified2_type_masks->{$UNIFIED2_EXTRA_DATA});
       @record = unpack($unified2_type_masks->{$UNIFIED2_EXTRA_DATA}, $buffer);
       foreach my $fld (@{$UF_Record->{'FIELDS'}}) {
           if ($fld ne 'data_blob') {
                $UF_Record->{$fld} = $record[$i++];
                debug("Field " . $fld . " is set to " . $UF_Record->{$fld});
           } else {
               debug("Filling in data_blob with " . $UF_Record->{'bloblength'} . " byes");
               # XXX - JRB - I'm stealing this from the packet code above but WTH is it * -1?
               # Something tells me it should be -1 not * -1 too bad I didn't comment it
               $UF_Record->{$fld} = substr($buffer, $UF_Record->{'bloblength'} * -1, $UF_Record->{'bloblength'});
               
               # With XFF (type 1) you have two size fields and then the data. You have the size of the blob,
               # the size of the data, and the data
               # to handle it in your application you would do
               # register_handler("unified2_extra_data", \&xff_handler)
           }
       }
       exec_handler("unified2_extra_data", $UF_Record);
    } else {
        debug("Handling of type " . $UF_Record->{'TYPE'} . " not implemented yet");
        exec_handler("unified2_unhandled", $UF_Record);
        return undef;
    }
        
    exec_handler("unified2_record", $UF_Record);

    if ( exec_qualifier($UF_Record->{'TYPE'},$UF_Record->{'sig_gen'},$UF_Record->{'sig_id'}, $UF_Record) ) {
        return $UF_Record;
    }
    
    # presume something is not right
    return -1;
}

###############################################################
# A stub to call the right readrecord func
###############################################################
sub readSnortUnifiedRecord() {
    my $rec = undef;

    if ( $UF->{'TYPE'} eq $UNIFIED_ALERT || $UF->{'TYPE'} eq $UNIFIED_LOG ) {
        $rec = old_readSnortUnifiedRecord();
        while ( $rec == -1 ) {
            $rec = old_readSnortUnifiedRecord();
        }
    } elsif ( $UF->{'TYPE'} eq $UNIFIED2 ) {
        $rec = readSnortUnified2Record();
        while ( $rec == -1 ) {
            $rec = readSnortUnified2Record();
        }
    } else {
        cluck("readSnortUnifiedRecord does not handle " . $UF->{'TYPE'} . " files");
        return undef;
    }

    return $rec;
}

###############################################################
# Read old unified record formats
###############################################################
sub old_readSnortUnifiedRecord() {

    if ( $UF->{'TYPE'} ne $UNIFIED_ALERT && $UF->{'TYPE'} ne $UNIFIED_LOG ) {
        cluck("readSnortUnifiedRecord does not handle " . $UF->{'TYPE'} . " files");
        return undef;
    } else {
        debug("Handling $UF->{'TYPE'} file");
    }

    my $buffer = '';
    my $readsize = 0;
    my $pktsize = 0;
    my $size = 0;
    my $mtime = 0;
    my $fsize;
    my @fields;
    my $i=0;

    $UF_Record = undef;
    $UF->{'FILESIZE'} = (stat(UFD))[7];
    $UF->{'FILEMTIME'} = (stat(UFD))[9];

    ($readsize,$buffer) = readData($UF->{'RECORDSIZE'}, $UF->{'TOLERANCE'});

    if ( $readsize <= 0) {
        return undef;
    }

    $UF_Record->{'raw_record'} = $buffer;

    # if ( read(UFD, $buffer, $UF->{'RECORDSIZE'}) != $UF->{'RECORDSIZE'}) { return undef; }

    # It seems that writing into the array as follows is approximately 3x slower
    # than reading into an array and converting
    # ($a,$b,$c) = ( unpack('NNN',$buffer)
   
    @fields = unpack($UF->{'PACKSTR'}, $buffer);
    if ( $debug ) {
        $i = 0;
        foreach my $field (@{$UF->{'FIELDS'}}) {
            debug(sprintf("Field %s is %x\n", $field, $fields[$i++]));
        }
    }
    $i = 0;
    # Make FIELDS available in all records
    $UF_Record->{'FIELDS'} = $UF->{'FIELDS'};

    foreach my $field (@{$UF->{'FIELDS'}}) {
        if ( $field eq 'pkt' ) {
	        if ( $UF_Record->{'caplen'} >= 65536 ) {
                debug(sprintf("BAIL: Got an absurd packet size of %d. Assuming corrupt unified file\n",$UF_Record->{'caplen'}));
                return undef;
            }
            debug(sprintf("FETCHING PACKET OF SIZE %d IN readSnortUnifiedRecord\n", $UF_Record->{'caplen'}));
            ( $pktsize, $UF_Record->{$field}) = readData($UF_Record->{'caplen'}, $UF->{'TOLERANCE'});
        
            if ( $pktsize != $UF_Record->{'caplen'} ) {
                return undef;
            }

        } else {
            debug(sprintf("SETTING FIELD %s with data %d long\n", $field, length($fields[$i])));
            $UF_Record->{$field} = $fields[$i++];
        }
    }

    exec_handler("unified_record", $UF_Record);

    if ( exec_qualifier(0,$UF_Record->{'sig_gen'},$UF_Record->{'sig_id'}, $UF_Record) ) {
        return $UF_Record;
    }

    # presume something is not right
    return -1;

}


###############################################################
# Handle reading data from a file, tail it of we are told to
# return bytes read, buffer and place data in raw_data
# BTW: this is a quick fix working within stuff. I need to redo
# all of this as it is clear unified is going to evolve
# with more compled record types and the first iteration
# was/is a quickie
###############################################################
sub readData() {
    my $size = $_[0];
    my $tolerance = $_[1];

    my $buffer = undef;
    my $readsize = 0;
    my $deads = 0;
    my $fsize = 0;
    my $mtime = 0;


    $readsize = read(UFD, $buffer, $size, $readsize);
    while ( $readsize != $size ) {
        # reset EOF condition if it exists
        seek(UFD, $UF->{'FILEPOS'}+$readsize, 0);
        $readsize += read(UFD, $buffer, $size-$readsize, $readsize);
        $fsize = (stat(UFD))[7];
        $mtime = (stat(UFD))[9];

        debug("Read $readsize bytes so far in readData.");
        debug("fpos is $fsize:$UF->{'FILEPOS'} in readData.");
        debug("mtime is $mtime:$UF->{'FILEMTIME'} in readData.");

        # if the file is unchanged track dead reads
        if ( ( $mtime eq $UF->{'FILEMTIME'} ) &&
             ( $fsize eq $UF->{'FILESIZE'} ) &&
             ( $fsize eq $UF->{'FILEPOS'} )) {
            $deads++;
            if ( $tolerance == 0 || $deads % $tolerance == 0 ) {
                debug("Bailing on deads of $deads in readData");
                debug("Seeking to $UF->{'FILEPOS'}");
                seek(UFD, $UF->{'FILEPOS'}, 0);
                return (-1,undef);
            }
            $UF->{'FILEMTIME'} = $mtime;
            $UF->{'FILESIZE'} = $fsize;
        }
        sleep $UF->{'PATIENCE'};
    }
    $UF->{'FILEPOS'} += $readsize;
    $UF->{'FILESIZE'} = $fsize;
    $UF->{'FILEMTIME'} = $mtime;
    #Expose the raw data
    $UF_Record->{'raw_record'} = $buffer;

    exec_handler("read_data", ($readsize, $buffer));

    return ($readsize, $buffer);
}


###############################################################
# Populate the header information for the unified file
###############################################################
sub readSnortUnifiedHeader($) {
    my $h = $_[0];
    my $buff;
    my $header = 0;
  
    # Reset at beginning of file
    seek(UFD,0,0);

    if ( $h->{'TYPE'} eq $UNIFIED_LOG ) {
        $header += read(UFD, $buff, 4);
        $h->{'MAGIC'} = unpack($h->{'4'}, $buff);
        $header += read(UFD, $buff, 2);
        $h->{'VERSION_MAJOR'} = unpack($h->{'2'}, $buff);
        $header += read(UFD, $buff, 2);
        $h->{'VERSION_MINOR'} = unpack($h->{'2'}, $buff);
        $header += read(UFD, $buff, 4);
        $h->{'TIMEZONE'} = unpack($h->{'4'}, $buff);
        $header += read(UFD, $buff, 4); 
        $h->{'SIG_FLAG'} = unpack($h->{'4'}, $buff);
        $header += read(UFD, $buff, 4);
        $h->{'SLAPLEN'} = unpack($h->{'4'}, $buff);
        $header += read(UFD, $buff, 4);
        $h->{'LINKTYPE'} = unpack($h->{'4'}, $buff);
    } elsif ($h->{'TYPE'} eq $UNIFIED_ALERT) {
        $header += read(UFD, $buff, 4);
        $h->{'MAGIC'} = unpack($h->{'4'}, $buff);
        $header += read(UFD, $buff, 4);
        $h->{'VERSION_MAJOR'} = unpack($h->{'4'}, $buff);
        $header += read(UFD, $buff, 4);
        $h->{'VERSION_MINOR'} = unpack($h->{'4'}, $buff);
        $header += read(UFD, $buff, 4);
        $h->{'TIMEZONE'} = unpack($h->{'4'}, $buff);
    } elsif ( $h->{'TYPE'} eq $UNIFIED2 ) {
        debug("Nothing to handle for unified2");
    } else {
        # XXX - Fallthrough 
        debug("Fallthrough in readSnortUNifiedHeader");
    }
    $UF->{'FILEPOS'} = $header;
    
    exec_handler("read_header", $h);

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
