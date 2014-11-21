package SnortUnified::Database;

#########################################################################################
#  $VERSION = "SnortUnified to MySql 1.0 - Copyright (c) 2007 Jason Brvenik";
# 
# A Perl module to insert snort data from a unified file into a mysql database.
# http://www.snort.org
#
# 
#########################################################################################
# 
#
# The intellectual property rights in this program are owned by 
# Jason Brvenik.  This program may be copied, distributed and/or 
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
#########################################################################################
# Changes:
#########################################################################################
# TODO: in no specific order
#  - Documentation
# 
#########################################################################################
# NOTES:
#########################################################################################
# NOTE to self:
# 
# I've chosen to use internal globals so that routines can be selectively overridden
# in the future if needed without a lot of parameter passing.
# 
# EG: You could use this method to choose a routine to map into
# instead of the default.
# *{getSnortSensorID} = sub { SomeDatabaseGetSnortSensorID();};
#
# This will be useful _if_ there is a quirk somewhere that DBI does not handle
# and there is no easy way to fix it in teh existing routine.
#########################################################################################

use strict;
require Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

use DBI;
use POSIX qw(strftime); 
use Socket;
use NetPacket::Ethernet qw(:ALL);
use NetPacket::IP qw(:ALL);
use NetPacket::TCP qw(:ALL);
use NetPacket::UDP qw(:ALL);
use NetPacket::ICMP qw(:ALL);
use SnortUnified::Handlers qw(:ALL);

my $class_self;

BEGIN {
   $class_self = __PACKAGE__;
   $VERSION = "1.3devel";
}
my $DBLICENSE = "GNU GPL see http://www.gnu.org/licenses/gpl.txt for more information.";
sub DBVersion() { "$class_self v$VERSION - Copyright (c) 2006 Jason Brvenik" };
sub DBLicense() { DBVersion . "\nLicensed under the $DBLICENSE" };

# Pollute global namespace
@ISA = qw(Exporter);
@EXPORT = qw(
                DBLicense
                DBVersion
                getSnortDBHandle
                closeSnortDBHandle
                setSnortConnParam
                printSnortConnParams
                getSnortSensorID
                insertSnortAlert
                insertSnortLog
);

@EXPORT_OK = qw(
                $DB_INFO
                $SIG_ID_MAP
                printSnortSigIdMap
                $DBH
             );

%EXPORT_TAGS = (
               ALL => [@EXPORT, @EXPORT_OK],
);


our $DBH = undef;
our $SIG_ID_MAP = undef;
our $CLASS_ID_MAP = undef;
our $DB_INFO = { 
                'type'           => 'mysql',
                'host'           => 'localhost',
                'port'           => 3306,
                'database'       => 'snort',
                'user'           => 'snortuser',
                'password'       => 'snortpass',
                'connstr'        => 'DBI:mysql:database=snort;host=localhost;port=3306',
                'sensor_id'      => 0,
                'linktype'       => 0,
                'interface'      => '',
                'hostname'       => 'localhost',
                'filter'         => '',
                'payload'        => 1,
                'event_id'       => 0,
              };

my $REQUIRED_SCHEMA = 106;
my $SIG_MAP_H = undef;
my $CLASS_MAP_H = undef;
my $REF_MAP_H = undef;
my $EVENT_INS_H = undef;
my $IPH_INS_H = undef;
my $TCP_INS_H = undef;
my $UDP_INS_H = undef;
my $ICMP_INS_H = undef;
my $IPHDR_INS_H = undef;
my $TCPHDR_INS_H = undef;
my $UDPHDR_INS_H = undef;
my $ICMPHDR_INS_FULL_H = undef;
my $ICMPHDR_INS_H = undef;
my $REFERENCE_INS_H = undef;
my $PAYLOAD_DATA_INS_H = undef;

sub setSnortConnParam($$) {
    my $parm = $_[0];
    my $val = $_[1];

    $DB_INFO->{$parm} = $val;
    if ( $DB_INFO->{'type'} eq 'mysql' ) {
        $DB_INFO->{'connstr'} = "DBI:" . $DB_INFO->{'type'} . 
            ":database=" . $DB_INFO->{'database'} . 
            ";host=" . $DB_INFO->{'host'} .
            ";port=" . $DB_INFO->{'port'} .
            ";";
    } else {
        print("Database " . $DB_INFO->{'database'} . " not supported\n");
    }

}

sub printSnortConnParams() {
    my $sid;
    my $rev;
    foreach my $key ( keys %{$DB_INFO} ) {
        print("$key     \t: " . $DB_INFO->{$key} . "\n");
    }
}

sub printSnortSigIdMap() {
    print("Dumping sid->sig map\n");
    foreach my $key (sort keys %{$SIG_ID_MAP}) {
        print("$key\t: " . $SIG_ID_MAP->{$key} . "\n");
    }
}

sub printSnortClassIdMap() {
    print("Dumping class->id map\n");
    foreach my $key ( sort keys %{$CLASS_ID_MAP} ) {
        print("$CLASS_ID_MAP->{$key}:$key\n");
    }
}

sub getSnortDBHandle() {

    my $schema = 0;

    $DBH = DBI->connect($DB_INFO->{'connstr'}, $DB_INFO->{'user'}, $DB_INFO->{'password'}); 
    
    # XXX - Need to fix for 5.0
    # ($schema) = $DBH->selectrow_array("SELECT max(vseq) from schema");
    ($schema) = $DBH->selectrow_array("SELECT max(vseq) from `schema`");
    
    if ( $schema lt $REQUIRED_SCHEMA ) { 
        print("Schema Version " . $schema . " too old\n"); 
        return 0;
    } else {
        return 1;
    }
}

sub closeSnortDBHandle() {

    $DBH->disconnect();
}

sub getSnortSensorID() {

    my $sid = 0;
    my $qh;

    $qh = $DBH->prepare("SELECT sid FROM sensor WHERE " . 
                        "hostname=? AND " . 
                        "interface=? AND " .
                        "filter=? AND " . 
                        "detail=? AND " .
                        "encoding='0'");

    $qh->execute($DB_INFO->{'hostname'}, 
                 $DB_INFO->{'interface'}, 
                 $DB_INFO->{'filter'}, 
                 $DB_INFO->{'payload'}) || print("error " . $qh->errstr . "\n");;

    ($sid) = $qh->fetchrow_array();
    
    if ( !defined $sid ) {
        $qh = $DBH->prepare("INSERT INTO sensor(hostname,interface,filter," .
                            "detail,encoding,last_cid) VALUES (?,?,?,?,'0','0')");

        $qh->execute($DB_INFO->{'hostname'}, 
                     $DB_INFO->{'interface'}, 
                     $DB_INFO->{'filter'}, 
                     $DB_INFO->{'payload'}) || print("error " . $qh->errstr . "\n");

        $qh = $DBH->prepare("SELECT sid FROM sensor WHERE " . 
                            "hostname=? AND " . 
                            "interface=? AND " . 
                            "filter=? AND " . 
                            "detail=? AND " .
                            "encoding='0'");

        $qh->execute($DB_INFO->{'hostname'}, 
                     $DB_INFO->{'interface'}, 
                     $DB_INFO->{'filter'}, 
                     $DB_INFO->{'payload'}) || print("error " . $qh->errstr . "\n");

        ($sid) = $qh->fetchrow_array();
    }

    $DB_INFO->{'sensor_id'} = $sid;

    # get the next event ID for this sensor
    ($DB_INFO->{'event_id'}) = $DBH->selectrow_array("SELECT max(cid) FROM " . 
                                                     "event WHERE sid=" . $sid);
    $DB_INFO->{'event_id'}++;

    # build the sig_id map and cache it for use
    # XXX - Note: This differs from barnyard somewhat...
    # barnyard uses the rule text in combination with the sid:rev
    # I'm using gen:sid:rev ignoring the message text as that will be pulled 
    # from the sidmap at the time of insert

    $qh = $DBH->prepare("SELECT sig_gid,sig_sid,sig_rev,sig_id,sig_name FROM signature");
    $qh->execute;

    my $sidref;
    while ( $sidref = $qh->fetchrow_hashref() ) {
        my $gensid = $sidref->{'sig_gid'}.":".$sidref->{'sig_sid'};
        $SIG_ID_MAP->{$gensid}->{'id'} = $sidref->{'sig_id'};
        $SIG_ID_MAP->{$gensid}->{'msg'} = $sidref->{'sig_name'};
        $SIG_ID_MAP->{$gensid}->{'gid'} = $sidref->{'sig_gid'};
        $SIG_ID_MAP->{$gensid}->{'sid'} = $sidref->{'sig_sid'};
    }

    # Build the classification map
    $qh = $DBH->prepare("SELECT sig_class_id, sig_class_name FROM sig_class");
    $qh->execute;
    my $classref;
    while ( $classref = $qh->fetchrow_hashref() ) {
        $CLASS_ID_MAP->{$classref->{'sig_class_name'}} = $classref->{'sig_class_id'};
    }

    return $sid;
}

sub getSigID($$$) {
    my $record = $_[0];
    my $sids = $_[1];
    my $class = $_[2];
    my $classid = getClassID($record, $class)||0;
    my $sidref;
    my $gensid = "$record->{'sig_gen'}:$record->{'sig_id'}";
    my $msg = $sids->{$record->{'sig_gen'}}->{$record->{'sig_id'}}->{'msg'};

    # sometimes we get events for things that were not updated
    # in sid-msg.map 
    # Most commonly this is for local rules
    # Using UNKNOWN for the sig message in this case
    $msg = defined $msg?$msg:"UNKNOWN";

    if ( defined $SIG_ID_MAP->{$gensid}->{'id'} ) {
        return $SIG_ID_MAP->{$gensid}->{'id'};
    }

    # in case someone slipped it in on us
    my $qh = $DBH->prepare("SELECT sig_gid,sig_sid,sig_rev,sig_id,sig_name FROM signature " .
                           "WHERE sig_gid=? AND sig_sid=?");
    $qh->execute($record->{'sig_gen'}, $record->{'sig_id'});
    $sidref = $qh->fetchrow_hashref();

    if ( !defined $sidref ) {
        if ( !defined $SIG_MAP_H ) {
            $SIG_MAP_H = $DBH->prepare("INSERT INTO " . 
               "signature(sig_name, sig_class_id, sig_priority, sig_rev, sig_sid, sig_gid) " . 
               "VALUES(?, ?, ?, ?, ?, ?)");
        }

        $SIG_MAP_H->execute($msg,
                   $record->{'class'},
                   $record->{'pri'},
                   $record->{'sig_rev'},
                   $record->{'sig_id'},
                   $record->{'sig_gen'});

        $qh->execute($record->{'sig_gen'}, $record->{'sig_id'});
        $sidref = $qh->fetchrow_hashref();

        $SIG_ID_MAP->{$gensid}->{'id'} = $sidref->{'sig_id'};
        $SIG_ID_MAP->{$gensid}->{'msg'} = $sidref->{'sig_name'};
        $SIG_ID_MAP->{$gensid}->{'gid'} = $sidref->{'sig_gid'};
        $SIG_ID_MAP->{$gensid}->{'sid'} = $sidref->{'sig_sid'};
        
        # XXX - Need to add reference handling
    } else {
        $SIG_ID_MAP->{$gensid}->{'id'} = $sidref->{'sig_id'};
        $SIG_ID_MAP->{$gensid}->{'msg'} = $sidref->{'sig_name'};
        $SIG_ID_MAP->{$gensid}->{'gid'} = $sidref->{'sig_gid'};
        $SIG_ID_MAP->{$gensid}->{'sid'} = $sidref->{'sig_sid'};
    }

    return $SIG_ID_MAP->{$gensid}->{'id'};
}

sub getClassID($$) {
    my $record = $_[0];
    my $class = $_[1];
    my $classid;
    my $msg = $class->{$record->{'class'}}->{'type'};

    $msg = defined $msg?$msg:"unclassified";

    if ( defined $CLASS_ID_MAP->{$msg} ) {
        return $CLASS_ID_MAP->{$msg};
    }

    # In case someone else slipped it in on us
    my $qh = $DBH->prepare("SELECT sig_class_id FROM sig_class where sig_class_name=?");
    $qh->execute($msg);
   
    ($classid) = $qh->fetchrow_array();
    if ( !defined $classid ) {
        if ( !defined $CLASS_MAP_H ) {
            $CLASS_MAP_H = $DBH->prepare("INSERT INTO sig_class(sig_class_name) VALUES(?)");
        }
        $CLASS_MAP_H->execute($msg);
        $qh->execute($msg);
        ($classid) = $qh->fetchrow_array();
        $CLASS_ID_MAP->{$msg} = $classid;
    }
    
    return $CLASS_ID_MAP->{$msg};
}

sub getReferenceID() {
    my $record = $_[0];

}

sub check_handles() {
    if ( !defined $EVENT_INS_H ) {
        $EVENT_INS_H = $DBH->prepare("INSERT INTO " .
                                     "event(sid, cid, signature, timestamp) " .
                                     "VALUES(?, ?, ?, ?)");
    }

    if ( !defined $IPH_INS_H ) {
        $IPH_INS_H = $DBH->prepare("INSERT INTO " .
                                   "iphdr(sid, cid, ip_src, ip_dst, ip_proto) " .
                                   "VALUES(?, ?, ?, ?, ?)");
    }

    if ( !defined $TCP_INS_H ) {
        $TCP_INS_H = $DBH->prepare("INSERT INTO " .
                                   "tcphdr (sid, cid, tcp_sport, tcp_dport, tcp_flags) " .
                                   "VALUES(?, ?, ?, ?, 0)");
    }

    if ( !defined $UDP_INS_H ) {
        $UDP_INS_H = $DBH->prepare("INSERT INTO " .
                                   "udphdr (sid, cid, udp_sport, udp_dport) " .
                                   "VALUES(?, ?, ?, ?)");
    }

    if ( !defined $ICMP_INS_H ) {
        $ICMP_INS_H = $DBH->prepare("INSERT INTO " .
                                    "icmphdr (sid, cid, icmp_type, icmp_code) " .
                                    "VALUES(?, ?, ?, ?)");
    }

    if ( !defined $IPHDR_INS_H ) {
        $IPHDR_INS_H = $DBH->prepare("INSERT INTO iphdr(sid, cid, ip_src, ip_dst, ip_proto, " .
                                 "ip_ver, ip_hlen, ip_tos, ip_len, ip_id, ip_flags, ip_off, ".
                                 "ip_ttl, ip_csum) " .
                                 "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    }
    
    if ( !defined $TCPHDR_INS_H ) {
        $TCPHDR_INS_H = $DBH->prepare("INSERT INTO tcphdr(sid, cid, tcp_sport, tcp_dport, " . 
                                 "tcp_seq, tcp_ack, tcp_off, tcp_res, tcp_flags, tcp_win, " . 
                                 "tcp_csum, tcp_urp) " . 
                                 "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    }
 
    if ( !defined $UDPHDR_INS_H ) {
        $UDPHDR_INS_H = $DBH->prepare("INSERT INTO " . 
                                 "udphdr(sid, cid, udp_sport, udp_dport, udp_len, udp_csum) " .
                                 "VALUES(?, ?, ?, ?, ?, ?)");

    }
    
    if ( !defined $ICMPHDR_INS_FULL_H ) {
        $ICMPHDR_INS_FULL_H = $DBH->prepare("INSERT INTO " . 
                                 "icmphdr(sid, cid, icmp_type, icmp_code, icmp_csum, icmp_id, " . 
                                 "icmp_seq) " . 
                                 "VALUES(?, ?, ?, ?, ?, ?, ?)");
    }

    if ( !defined $ICMPHDR_INS_H ) {
        $ICMPHDR_INS_H = $DBH->prepare("INSERT INTO " . 
                                 "icmphdr(sid, cid, icmp_type, icmp_code, icmp_csum) " . 
                                 "VALUES(?, ?, ?, ?, ?)");
    }

    if ( !defined $PAYLOAD_DATA_INS_H) {
        $PAYLOAD_DATA_INS_H = $DBH->prepare("INSERT INTO " .
                                  "data(sid, cid, data_payload) " .
                                  "VALUES(?, ?, ?)")
    }

};

sub insertSnortAlert($$$) {
    my $record = $_[0]; # hash with the actual data
    my $sids = $_[1];   # Hash of sids
    my $class = $_[2];  # Hash of classifications
    my $sigid;
    my $classid;
    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", gmtime($record->{'tv_sec'}));
    my $gensid = "$record->{'sig_gen'}:$record->{'sig_id'}";
    
    check_handles();

    exec_handler('pre_event_insert', $record);

    $sigid = getSigID($record, $sids, $class);
    $classid = getClassID($record, $class);
    

    $EVENT_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'}, 
                 $sigid, $timestamp);

    $IPH_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'},
                 $record->{'sip'}, $record->{'dip'}, $record->{'protocol'});

    if ( $record->{'protocol'} eq IP_PROTO_TCP ) {
        $TCP_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'},
                 $record->{'sp'}, $record->{'dp'});

    } elsif ( $record->{'protocol'} eq IP_PROTO_UDP ) {
        $UDP_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'},
                 $record->{'sp'}, $record->{'dp'});

    } elsif ( $record->{'protocol'} eq IP_PROTO_ICMP ) {
        $ICMP_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'},
                 $record->{'sp'}, $record->{'dp'});
    }
    
    # Increment the event ID
    $DB_INFO->{'event_id'}++;

    exec_handler('post_event_insert', $record);
}

sub insertSnortLog($$$) {
    my $record = $_[0]; # hash with the actual data
    my $sids = $_[1];   # Hash of sids
    my $class = $_[2];  # Hash of classifications
    my $sigid;
    my $classid;
    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", gmtime($record->{'tv_sec'}));
    my $gensid = "$record->{'sig_gen'}:$record->{'sig_id'}"; 
    my $eth_obj;
    my $ip_obj;
    my $tcp_obj;
    my $udp_obj;
    my $icmp_obj;
    my $hex_payload;
    my $hex_payload_len;
    my $icmp_header_size;


    check_handles();

    exec_handler('pre_log_insert', $record);

    $sigid = getSigID($record, $sids, $class) || 0;
    $classid = getClassID($record, $class) || 0;

    $EVENT_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'},
                 $sigid, $timestamp);

    $eth_obj = NetPacket::Ethernet->decode($record->{'pkt'});
    if ( $eth_obj->{type} eq ETH_TYPE_IP ) {
        $ip_obj = NetPacket::IP->decode($eth_obj->{data});
        $IPHDR_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'},
		# $ip_obj->{src_ip}, $ip_obj->{dest_ip},
		              unpack('N',inet_aton($ip_obj->{src_ip})), unpack('N',inet_aton($ip_obj->{dest_ip})),
                              $ip_obj->{proto}, $ip_obj->{ver},
                              $ip_obj->{hlen}, $ip_obj->{tos},
                              $ip_obj->{len}, $ip_obj->{id},
                              $ip_obj->{flags}, $ip_obj->{foffset},
                              $ip_obj->{ttl}, $ip_obj->{cksum});

        if ( $ip_obj->{proto} eq IP_PROTO_TCP ) {
            $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
            $TCPHDR_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'},
                                   $tcp_obj->{src_port}, $tcp_obj->{dest_port},
                                   $tcp_obj->{seqnum}, $tcp_obj->{acknum},
				   # (($tcp_obj->{reserved} & 0xf0) >> 4),
				   $tcp_obj->{hlen},
                                   ($tcp_obj->{reserved} & 0x0f),
                                   $tcp_obj->{flags}, $tcp_obj->{winsize},
                                   $tcp_obj->{cksum}, $tcp_obj->{urg});

             # XXX - revisit this
             $hex_payload_len = ($ip_obj->{len} * 2 - $ip_obj->{hlen} * 8 - $tcp_obj->{hlen} * 8);
	     $hex_payload = uc(unpack("H*",$tcp_obj->{'data'}));
	     if($hex_payload_len > 0 && $hex_payload =~ /^([0-9A-F]{$hex_payload_len})/) {
                 $PAYLOAD_DATA_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'}, $1);
             }

        } elsif ( $ip_obj->{proto} eq IP_PROTO_UDP ) {
            $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
            $UDPHDR_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'},
                                   $udp_obj->{src_port}, $udp_obj->{dest_port},
                                   $udp_obj->{len}, $udp_obj->{cksum});
             
            # XXX - revisit this
            $hex_payload_len = ($ip_obj->{len} * 2 - $ip_obj->{hlen} * 8 - 16);
	    $hex_payload = uc(unpack("H*",$udp_obj->{'data'}));
	    if($hex_payload_len > 0 && $hex_payload =~ /^([0-9A-F]{$hex_payload_len})/) {
                $PAYLOAD_DATA_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'}, $1);
	    }

        } elsif ( $ip_obj->{proto} eq IP_PROTO_ICMP ) {
            $icmp_obj = NetPacket::ICMP->decode($ip_obj->{data});
            if ( $icmp_obj->{type} eq 0 || $icmp_obj->{type} eq 8 ||
                 $icmp_obj->{type} eq 13 || $icmp_obj->{type} eq 14 ||
                 $icmp_obj->{type} eq 15 || $icmp_obj->{type} eq 16 ) {
                 $ICMPHDR_INS_FULL_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'},
                                   $icmp_obj->{type}, $icmp_obj->{code},
                                   $icmp_obj->{cksum}, 
                                   unpack('n', substr($icmp_obj->{data}, 0, 2)),
                                   unpack('n', substr($icmp_obj->{data}, 2, 2)));
            } else {
                 $ICMPHDR_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'},
                                   $icmp_obj->{type}, $icmp_obj->{code},
                                   $icmp_obj->{cksum});

                 # XXX - revisit this
                 $hex_payload = uc(unpack("H*",$icmp_obj->{'data'}));
		 if ($icmp_obj->{type} == 0 || $icmp_obj->{type} == 8) {
                     $hex_payload_len = ($ip_obj->{len} * 2 - 56);
		     if($hex_payload =~ /.*([0-9A-F]{$hex_payload_len})$/) {
                         $hex_payload = $1;
                     }
		 }
		 $PAYLOAD_DATA_INS_H->execute($DB_INFO->{'sensor_id'}, $DB_INFO->{'event_id'}, $hex_payload);

            }
        } else {
            # print("DEBUGME: Why am I here - insertSnortLog\n");
        }
    }

    $DB_INFO->{'event_id'}++;
    
    exec_handler('post_log_insert', $record);

}
1
