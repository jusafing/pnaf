# PASSIVE NETWORK AUDIT FRAMEWORK (PNAF) v0.1.2
-----

Copyright (C) 2014 Javier Santillan

PNAF v0.1.1 public prototype is an implementation of a TU/e master thesis developed as internship project at Fox-IT B.V in The Netherlands. This public prototype DOES NOT include any internal information about TU/e nor Fox-IT.

From Version 0.1.2, PNAF is a project of UNAM-Chapter [The Honeynet Project]
* http://blog.honeynet.org.mx
* http://pnaf.honeynet.org.mx
* http://sec.jusanet.org
* http://www.honeynet.unam.mx

Version 0.1.2 will get just minor updates (bugs/parsing) and it is the last version of 0.1.x branch. You can either clone this repository and install it on your standalone machine, or download the Virtual Machine image available on http://pnaf.honeynet.org.mx/download/

The next version of PNAF is 0.2.x and it is the current main dev project. It will contain significant changes (dockerized, improved installation, parsing, daemon model, multi-threading support, etc). If you have any feedback/idea please drop an email (see contact information below).

## SUMMARY
PNAF is a framework intended to provide the capability of getting a security assessment of network plattforms by analysing in-depth the network traffic (in a passive way) and by providing a high-level interpretation in an automated way. It combines different analysis techniques and tools. The framework is intended to achieve the following goals:
#####  Architecture
* To be a flexible, scalable and modular framework
* To provide accurate analysis of network plattforms
* To provide a useful API in order to develop further features and improvements (not included on 0.1.2 prototype, but on next 0.2.x)
##### Functional
* Summary of the Security Level of the network
* Findings of anomalous activities
* Findings of security audit policy
* Findings of impact analysis (e.g. based on CVE)
* Summary of security recommendations
* Reference of evidence

## ARCHITECTURE

PNAF is comprised by three main modules. Each module has its own engines which manage specific tools and process the data.
PNAF is written in Perl, why?  because Perl rules!

#### DCM - DATA COLLECTION MODULE
1. NTCE	- Network Traffic Capture Engine
2. NCPE	- Network Traffic Pre-processing Engine

#### DPM - DATA PROCESSING MODULE
##### &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; NPEE	- Network Profiling and Enumeraton Engine
* p0f	: Network and service enumeration 
* prads	: Network and service enumeration
##### &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; IDSE - Network Intrusion Detection Engine
* Suricata
* Snort
* Bro
* Barnyard : Unified2 reader
##### &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; NFAE - Network Flow Analysis Engine
* Cxtracker  : Basic flow data summary
* Argus      : Flow data analysis
* Yaf        : Flow data analysys
* Silk       : Flow data analysys
* Tcpdstat   : Protocol statistics
##### &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; DPIE - Deep Packet Inspection Engine
* Chaoreader : Application data extraction "any-snarf"
* Nftracker  : File extraction
* Xplico     : Application data extraction (url, files, ...)
* Httpry     : HTTP data logger
* Ssldump    : SSLv3/TLS data tracker
* Dnsdump    : DNS data extraction
* Passivedns : Passive DNS data collection
* Dnscap     : DNS capture utility (tcpdump-like for DNS)
* Tcpxtract  : File extraction
* Tcpdump    : Pcap filtering
##### &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; NSAE - Network Security Audit Engine
* Pnaf-auditor


### DVM - DATA VISUALIZATION MODULE (TODO -- Dev)
* WDVE	- Web Data Visualization Engine
* GSVE	- Graphic Security Visualization Engine
* SARE	- Security Audit Report Engine
* DIEE	- Data Import/Export Engine

# REQUIREMENTS
The current version has been tested on GNU/Linux Debian (6.x or later) and Gentoo (Stage 3) distributions. The main installer prepares automatically the whole environment by compiling all the tools included within the framework as well as their dependencies.

Since the installer downloads some packages using either apt or emerge depending on the distribution, then the installer needs to have access to Internet. Otherwise you can use the option '--no-packages' and then install by yourself the following packages/libraries:

##### APT packages:
    autoconf automake binutils-dev bison build-essential byacc ccache cmake dsniff flex g++ gawk gcc libcap-ng-dev libcli-dev libdatetime-perl libdumbnet-dev libfixposix0 libfixposix-dev libgeoip-dev zlib1g zlib1g-dev libgetopt-long-descriptive-perl libglib2.0-cil-dev libjansson4 libjansson-dev libldns-dev liblzo2-2 libnet1-dev libmagic-dev libmysql++3 libmysqlclient-dev libmysql++-dev libnacl-dev libncurses5-dev libldns1 libnetfilter-conntrack-dev libnetfilter-queue1 libnetfilter-queue-dev libnet-pcap-perl libnfnetlink0 libnfnetlink-dev libnl-3-dev libnl-genl-3-dev libpcap-dev libpcre3 libpcre3-dbg libpcre3-dev libsqlite3-dev libssl-dev liburcu-dev libyaml-0-2 libyaml-dev liblzo2-dev openssl pkg-config python-dev python-docutils sqlite3 swig git-core libglib2.0-dev libtool tcpslice tcpick tshark tcpflow ethtool

#### Emerge sources
    autoconf automake binutils bison libtool byacc ccache cmake flex gawk gcc dev-util/cmake sys-libs/libcap-ng dev-perl/glib-perl dev-libs/jansson dev-libs/lzo net-libs/libnet dev-libs/libnl virtual/perl-libnet dev-libs/geoip net-libs/libnetfilter_queue net-libs/libnetfilter_conntrack perl-core/libnet dev-perl/Net-PcapUtils dev-perl/Net-Pcap net-libs/libnfnetlink dev-db/sqlite dev-libs/libyaml dev-lang/swig net-analyzer/tcpflow dev-libs/libcli net-analyzer/dsniff dev-perl/DateTime ethtool

##### Additionally you need to install the following Perl Modules
    Config::Auto Pod::Usage  Proc::Daemon IO::CaptureOutput JSON:XS Cwd JSON::Parse Time::Piece Exception::Class Test::Warn Test::Differences Test::Deep Test::Most HTTP::BrowserDetect Getopt::Long String::Tokenizer URI::Encode Devel::Hexdump  Digest::MD5 Data::Dumper YAML NetPacket::Ethernet Net::Subnet

## INSTALLATION
You can install the whole framework (i.e. including the tools) by using the installer script. It has been tested on both Debian 7.x / Gentoo Stage 3 based systems (clean installation, base system, chrooted)

    ./install.sh

Alternatively you can install the Core Framework (without tools) by using the Makefile. In such a case you need to specify a bunch of option within the PNAF configuration file (binary files, configuration files, log dirs,..). For more information check out the 'build/pnaf/etc/pnaf.conf' file.

To install this module type the following:

    $ cd build/pnaf/Pnaf
    $ perl Makefile.PL
    $ make
    $ make test
    # make install 	// (as root)

## USAGE
    $ pnaf_auditor [options]

#### Options:
	Execution:
	--debug                 : Enable debug mode
	--conf                  : Specify configuration file (yaml)
	--help                  : Show this
	--version               : Show tools versions
	--parser arg1[,arg2]    : Specify parsers to be loaded
	    'p0f'               : Process enumeration data
	    'prads'             : Process enumeration data
	    'argusFlow'         : Process NFA data (flow analysis)
	    'snortAppId'        : Process enumeration data (App identification)
	    'httpry'            : DPI over HTTP (URL's, UA, etc)
	    'tcpdstat'          : Process enumeration data (protocol dist)
	    'suricataEve'       : Process IDS data (alerts and payloads)
	    'bro'               : DPI over different protocols
	    'tcpflow'           : Process NFA data (session tracking)
	--out_dataset           : Specify the kind of output data to generate
	    'all'               : Generate all datasets
	    'audit'             : Generate only audit dataset
	--home_net              : Specify the 'homenet' in CIDR format
	--payload               : Flag to enable payload decoding (IDS data)

	Inputs:
	--cap_file              : Set input capture file (pcap)
	--audit_dict            : Path to vulnerability dictionary
	--instance_dir          : Path to directory with 'initial raw dataset'

	Logging:
	--log_dir  		: Path to log directory
	--log_file 		: Path to output directory

    
### Examples
##### Perform a basic execution: All parsers/tools enabled
        $ pnaf_auditor --cap_file test1.cap --log_dir /pnaf/www/test1

##### Perform analysis of existing "raw logs" from tools
Note: input directory must contains actual raw logs that are generated by Tools (e.g. Snort unified2 files, Suricata JSON output, p0f logs, etc

    $ pnaf_auditor --instance_dir existinglogs --log_dir /pnaf/www/exlogs

##### Perform analysis of IDS tools only
    $pnaf_auditor --cap_file test2.cap --log_dir /pnaf/www/test2 --parser bro,snort,suricataEve

##### Perform analysis with homenet: When a homenet is specified, audit is focused only on homenet IP addresses/networks and Flow data (stats) are separated from External networks (useful to identify usage and filter out devices)

    $pnaf_auditor --cap_file test3.cap --log_dir /pnaf/www/test3 --homenet 192.168.1.0/14,192.168.2.30/27

##### Perform analysis decoding payloads from unified2 file (Snort) stored within a certain existing directory.

    $pnaf_auditor --instance_dir mysnortfiles --payload
    
### WEB VISUALIZATION
A (very) basic Web visualization can be used within PNAF.  

First, To start HTTP daemon:
    
    # /pnaf/bin/apachectl

Then, when executing pnaf_auditor, place output directories within /pnaf/www/. If you already got some outpudt directories, then copy them to this path.

Output data stored in '--log_dir' contains a tree as follows:

    DIRECTORY_NAME/                     (Raw logs genrated by tools)
    |
    |----- JSON/                        (Parsed files in JSON format)
    |       |
    |       |---SUMMARY/            (JSON tree view of dataset and audits)
    |       |   |                   (This is the main basic visualizer)
    |       |   |
    |       |   |---dataset         (Parsed data of all toolsets)
    |       |   |---auditSummary    (Summary of audit information)
    |       |   |---dataset.html    (All software found within trafic)
    |       |   |---auditOutput     (Audit based on CVE (NIST) and software)
    |       |   |---dataset.html    (Audit data sorted per single asset)
    |       |
    |       |-------VIEW1/          (Alternative JSON viewer)
    |       |
    |       |-------VIEWs/          (Deprecated)

## COPYRIGHT AND LICENSE
Copyright (C) 2014 by Javier Santillan
### Disclaimer
-----------
This framework contains external tools that have their own licenses. For more information about licensing you can read the corresponding licence files that are included within the tarballs that this framework uses for an automated installation. Such packages have not been modified and any information about licenses/authors is as it can be found on the corresponding releases (oficial websites, github, etc). For more information of versions used by this framework, you can check out the '--version' option of pnaf_auditor.

PNAF does not claim any rights, modifications nor ownerships. The PNAF core itself (Perl module included on this tarball within build/pnaf), is authored by -Javier Santillan- and the licence cited below applies only to PNAF itself.

-----------

PNAF core is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. 
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>. Also add information on how to contact you by electronic and paper mail.

PNAF v0.1.2  Copyright (C) 2014 Javier Santillan This program comes with ABSOLUTELY NO WARRANTY; for details type `--help' 
option on pnaf_auditor. This is free software, and you are welcome to redistribute it under certain conditions.

## TODO
- Provide a complete plattform-independent installation (Docker)
- Add additional parsers (for all tools within the framework)
- Frontend?
- Prototype version 0.1.2. Some parsers/functionalities from the original prototype are not included... YET. Next release will contain additional parsers/features

## CONTACT
###### For further updates visit:
* http://blog.honeynet.org.mx
* http://sec.jusanet.org

###### Oficial websites
* http://pnaf.honeynet.org.mx
* http://pnaf.jusanet.org

###### Related posts/info/howtos
* http://www.honeynet.unam.mx

###### Email
* Javier Santillan              <jusafing@honeynet.org.mx>
* HoneynetProject UNAM-Chapter  <contact@honeynet.org.mx> 

,
