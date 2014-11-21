#!/bin/bash
##############################################################################
##############################################################################
## Passive Network Audit Framework installer                                ##
## By Javier Santillan [jusafing@gmail.com] (2014)                          ##
## -------------------------------------------------------------------------##
## Requirements:                                                            ##
##	- Debian GNU/Linux 7.0.x					    ##
##	- Gentoo GNU/Linux stage3-x                                         ##
## Summary :                                                                ##
## 	Installation script of Passive Network Audit Framework v0.1         ##
##	It compiles and installs a set of traffic analysis tools.           ##
## 	See README file for more info.                                      ##
##############################################################################

##############################################################################
########################  VARIABLES CONFIGURATION    #########################
##############################################################################
INSTALLER_DIR=`pwd`
INSTALLER_LOGFILE="$INSTALLER_DIR/install.log"
INSTALLER_USER=`whoami`
BUILD_DIR="$INSTALLER_DIR/build"
OPT_OS="debian" #default Debian
#------------------------------------------------------------------------#
PNAF_DIR="/pnaf"
PNAF_SENSORNAME="Test"
PNAF_USER="pnaf"
DIALOG=${DIALOG=dialog}
PNAF_INSTALLER="PNAF Installer v0.1"
PNAF_EMERGE="/usr/bin/emerge"
PNAF_APT="/usr/bin/aptitude"
#------------------------------------------------------------------------#
TCPXTRACT_WEB="https://github.com/gamelinux/tcpxtract.git"
YAFWEB="http://tools.netsa.cert.org/yaf/download.html#"
SSLDUMP_WEB="http://www.rtfm.com/ssldump/ssldump-0.9b3.tar.gz"
BRO_WEB="http://www.bro.org/downloads/release/bro-2.2.tar.gz"
PASSIVEDNS_WEB="https://github.com/gamelinux/passivedns.git"
SNORT_WEB="https://www.snort.org/downloads/snort/snort-2.9.7.0.tar.gz"
HTTPD_WEB="http://apache.mirror.1000mbps.com//httpd/httpd-2.2.27.tar.gz"
HTTPRY_SRCFILE="$INSTALLER_WORKDIR/build/httpry.tar.gz"
CXTRACKER_WEB="https://github.com/gamelinux/cxtracker.git"
CHAOSREADER_WEB="https://github.com/firnsy/chaosreader2/archive/master.zip"
SURICATA_WEB="http://www.openinfosecfoundation.org/download/suricata-2.0.tar.gz"
IPFORENSICS_WEB="https://github.com/verisign/ipforensics"
TCPDUMP_WEB="http://www.rtfm.com/tcpdump/tcpdump-0.9b3.tar.gz"
NETSNIFF_WEB="https://github.com/netsniff-ng/netsniff-ng.git"
ARGUS_WEB="http://qosient.com/argus/src/argus-3.0.6.tar.gz"
DNSCAP_WEB="https://github.com/verisign/dnscap.git"
PRADS_WEB="https://github.com/gamelinux/prads.git"
NFTRACKER_WEB="https://github.com/gamelinux/nftracker.git"
P0F_WEB="http://lcamtuf.coredump.cx/p0f3/releases/p0f-3.06b.tgz"
# Github https://github.com/p0f/p0f.git
BARNYARD_WEB="https://github.com/firnsy/barnyard2.git"
SILK_WEB="http://tools.netsa.cert.org/silk/download.html#"
TCPDSTAT_WEB="https://github.com/netik/tcpdstat.git"
TCPFLOW_WEB="http://www.digitalcorpora.org/downloads/tcpflow/"
#------------------------------------------------------------------------#
TCPXTRACT="tcpxtract-1.0.1"
YAF="yaf-2.5.0"
LIBPCAP="libpcap-1.6.2"
SSLDUMP="ssldump-0.9b3"
DNSDUMP="dnsdump-1.11"
BRO="bro-2.3.1"
PASSIVEDNS="passivedns"
SNORT="snort-2.9.7.0"
HTTPD="httpd-2.2.27"
HTTPRY="httpry"
NDPI="nDPI"
XPLICO="xplico-1.1.0"
CXTRACKER="cxtracker"
CHAOSREADER="chaosreader"
SURICATA="suricata-2.0.4"
IPFORENSICS="ipforensics"
TCPDUMP="tcpdump-4.5.1"
NETSNIFF="netsniff-ng"
ARGUS_SERVER="argus-3.0.6"
ARGUS_CLIENT="argus-clients-3.0.6"
DNSCAP="dnscap"
PRADS="prads"
NFTRACKER="nftracker"
P0F="p0f-3.06b"
BARNYARD="barnyard2"
SILK="silk-3.8.1"
TCPDSTAT="tcpdstat"
TCPFLOW="tcpflow-1.3.0"
#------------------------------------------------------------------------#
SURICATA_LIBJANSSON_LIB="/usr/lib/i386-linux-gnu/"                              
SURICATA_LIBJANSSON_INC="/usr/include/"
##############################################################################
##############################################################################
##############################################################################
start()
{
    userInstall
    startConfirm
    selectTools
    installTools "$TOOLS"
    bannerLog
    installPnaf
    finalBanner
}
##############################################################################
logMsg()
{
    dialog --infobox "[$1] - $2" 5 65
    msg="[`date \"+%Y%m%d-%H:%M:%S\"`] [$1] - $2"
    echo $msg >> $INSTALLER_LOGFILE 
}
##############################################################################
execCmd()
{
    local fname="execCmd"
    cmd="$2"
    logMsg "$1 -> $FUNCNAME" " Executing: $2 ... "
    eval $cmd &>> $INSTALLER_LOGFILE.exec
    if [ $? -ne 0 ]; then
        logMsg "$FUNCNAME" "ERROR: Execution of $1 [$2]"
        exitInstall
    else
        logMsg "$FUNCNAME" " $1 [$2] ... OK"
    fi
}
##############################################################################
exitInstall()
{
    local fname="exitInstall"
    echo "The installation script has been terminated with errors"
    logMsg "$FUNCNAME" "The installation script has been terminated with \
	    errors. See install.log files for details."
    exit 1
}
##############################################################################
userInstall()
{
    if [ "$INSTALLER_USER" != "root" ]; then
    	echo ""
    	echo ""
    	echo "#####################################################"
        echo "# You must be root to run the installer             #"
        echo "#####################################################"
        echo ""
        echo ""
        exit 1
    fi
}
##############################################################################
exitInstaller()
{
    echo
    echo "#################################"
    echo "## PNAF Installer has finished ##"
    echo "#################################"
    echo
    exit 0
}
##############################################################################
startConfirm()
{
    local fname="startConfirm"
    logMsg "$FUNCNAME" "Preparing installer environment. See install.log \
	    files for detailed log ... (working)"
    if [ -x "$PNAF_APT" ]; then
        OPT_OS="debian"
        execCmd "$FUNCNAME" "aptitude update"
        execCmd "$FUNCNAME" "aptitude install -y dialog"
    elif [ -x "$PNAF_EMERGE" ]; then
        OPT_OS="gentoo"
        execCmd "$FUNCNAME" "emerge-webrsync"
        cmd="emerge --noreplace dialog"
        eval "$cmd" &>> $INSTALLER_LOGFILE.exec
        if [ $? -ne 0 ]; then
            logMsg "$FUNCNAME" "ERROR: Execution of ($cmd)"
            exitInstall
        else
            logMsg "$FUNCNAME" " $cmd ... OK"
        fi   
    else
        echo
        echo "ERROR. Unable to find emerge nor aptitude"
        exitInstall
    fi    
    $DIALOG --title "$PNAF_INSTALLER" --clear \
            --yesno "Welcome. Do you want to install PNAF\
		   on this system?" 7 70
    case $? in
	0)
	    echo "Starting PNAF installer.";;
	1)
	    exitInstaller;;
	255)
	    exitInstaller;;
    esac
}
##############################################################################
selectTools()
{
    tempfile=`tempfile 2>/dev/null` || tempfile=/tmp/test$$
    trap "rm -f $tempfile" 0 1 2 5 15

    $DIALOG --backtitle "$PNAF_INSTALLER" \
	    --title         "OS selection" --clear \
        --checklist     "Please select the operating system of this sensor"\
		                 20 61 15 \
	    "Prads"         "1-  Profiling and enumeration tool" on \
	    "P0f"	    "2-  Profiling and enumeration tool" on \
	    "Tcpdstat"	    "3-  Protocol Distribution" on \
	    "Suricata"	    "4-  Intrusion Detection system" on \
	    "Snort"	    "5-  Intrusion Detection system" on \
	    "Bro"	    "6-  Intrusion Detection Framework" on \
	    "Barnyard"	    "7-  Unified2 data logger" off \
	    "Cxtracker"	    "8-  Session Tracker" on \
	    "Argus"	    "9-  Network flow analyzer" on \
	    "Yaf"	    "10- Network Flow analyzer" off \
	    "Silk" 	    "11- Network Flow Analyzer" off \
	    "Tcpflow"	    "12- Network Flow Analyzer" on \
	    "Chaosreader"   "13- Application data analyzer" on \
	    "Xplico" 	    "14- Application data analyzer" off \
	    "Httpry" 	    "15- HTTP data extractor" on \
	    "Ssldump" 	    "16- SSLv3/TLS data tracker" on \
	    "Dnsdump" 	    "17- DNS data extractor" off \
	    "Dnscap" 	    "18- DNS data extractor" off \
	    "PassiveDNS"    "19- Passive DNS data collector" on \
	    "Nftracker"	    "20- File extractor" on \
	    "Tcpxtract"	    "21- File extractor" on \
	    "IPforensics"   "22- Network traffic analyzer" on \
	    "Tcpdump" 	    "23- Network traffic analyzer" on \
	    "Httpd"         "24- HTTP server (frontend visualization)" on\
	    "ConfTemplates" "25- Template configuration files" off\
	    2> $tempfile
    retval=$?
    TOOLS=`cat $tempfile`
    case $retval in
	0)
	    echo "PNAF installer will prepare installation environment \
		  for '$TOOLS' based system"
	    ;;
	1)
	    echo "Cancel pressed."
	    exitInstaller
	    ;;
	255)
	    echo "ESC pressed."
	    exitInstaller
	    ;;
    esac
}
##############################################################################
installTools()
{
    fname="installTools"
    makeDirs
    installPkg "$OPT_OS"
    logMsg "$FUNCNAME" "Installing selected tools ($TOOLS)"
    sleep 2
    for i in `echo $TOOLS| sed 's/"//g'`;
    do
	runInstaller $i
    done
}
##############################################################################
bannerLog()
{
    local fname="bannerLog"
    echo "##############################################"
    echo "PASSIVE AUDIT FRAMEWORK INSTALLATION"
    echo "##############################################"
    echo "______________________________________________"
    echo "Started @ [`date`]"                    
}
##############################################################################
cleanDir()
{
    local fname="cleanDir"
    if [ -d $1 ]; then
	logMsg "$FUNCNAME" "Cleaning existing $1 directory"
	execCmd "$FUNCNAME" "rm -rf $1" 
        # execCmd "$FUNCNAME" "mkdir -p $1"
    fi
}
##############################################################################
makeDirs()
{
    local fname="makeDirs"
    $DIALOG --title "$PNAF_INSTALLER" --clear \
            --yesno "Do you want to perform a clean installation? \
		     This will delete any existing PNAF installation" 7 70
    case $? in
	0)
	    cleanDir "$PNAF_DIR"
	    logMsg "$FUNCNAME" "#####################################"
	    logMsg "$FUNCNAME" "Creating PNAF directories"
	    execCmd "$FUNCNAME" "mkdir -p $PNAF_DIR/build"
	    execCmd "$FUNCNAME" "mkdir -p $PNAF_DIR/etc"
	    execCmd "$FUNCNAME" "mkdir -p $PNAF_DIR/bin"
	    execCmd "$FUNCNAME" "mkdir -p $PNAF_DIR/log"
	    execCmd "$FUNCNAME" "mkdir -p $PNAF_DIR/reports"
	    ;;
	1)
	    dialog --infobox "The installer will keep existing tools" 5 30;
	    sleep 1;
	    ;;
	255)
	    dialog --infobox "The installer will keep existing tools" 5 30;
	    sleep 1;
	    ;;
    esac
}
##############################################################################
installPnaf()
{
    local outdir="$PNAF_DIR/build/pnaf"
    logMsg "$FUNCNAME" "#####################################"
    logMsg "$FUNCNAME" "Installing PNAF modules"
    logMsg "$FUNCNAME" "Installing required CPAN modules"

    execCmd "$FUNCNAME" "cpan -i Config::Auto"
    execCmd "$FUNCNAME" "cpan -i Pod::Usage"
    execCmd "$FUNCNAME" "cpan -i Proc::Daemon"
    execCmd "$FUNCNAME" "cpan -i IO::CaptureOutput"
    execCmd "$FUNCNAME" "cpan -i JSON:XS"
    execCmd "$FUNCNAME" "cpan -i Cwd"
    execCmd "$FUNCNAME" "cpan -i JSON::Parse"
    execCmd "$FUNCNAME" "cpan -i Time::Piece"
    execCmd "$FUNCNAME" "cpan -i Exception::Class"
    execCmd "$FUNCNAME" "cpan -i Test::Warn"
    execCmd "$FUNCNAME" "cpan -i Test::Differences"
    execCmd "$FUNCNAME" "cpan -i Test::Deep"
    execCmd "$FUNCNAME" "cpan -i Test::Most"
    execCmd "$FUNCNAME" "cpan -i HTTP::BrowserDetect"
    execCmd "$FUNCNAME" "cpan -i Getopt::Long"
    execCmd "$FUNCNAME" "cpan -i String::Tokenizer"
    execCmd "$FUNCNAME" "cpan -i URI::Encode"
    execCmd "$FUNCNAME" "cpan -i Devel::Hexdump"
    execCmd "$FUNCNAME" "cpan -i Digest::MD5"
    execCmd "$FUNCNAME" "cpan -i Data::Dumper"
    execCmd "$FUNCNAME" "cpan -i YAML"
    execCmd "$FUNCNAME" "cpan -i NetPacket::Ethernet"
    execCmd "$FUNCNAME" "cpan -i Net::Subnet"
    logMsg "$FUNCNAME" "Installing PNAF prerequisite utilities"
    execCmd "$FUNCNAME" "cd $INSTALLER_DIR/build/SnortUnified"
    execCmd "$FUNCNAME" "perl Makefile.PL"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    cleanDir "$PNAF_DIR/www/json"
    execCmd "$FUNCNAME" "mkdir -p $PNAF_DIR/www"
    execCmd "$FUNCNAME" "cp -r $INSTALLER_DIR/build/json $PNAF_DIR/www/json"
    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/tmp/nvd.json \
			 $PNAF_DIR/etc/pnaf_dict.json"

    execCmd "$FUNCNAME" "mkdir -p $outdir"
    execCmd "$FUNCNAME" "cp -r $INSTALLER_DIR/build/pnaf/etc $outdir"
    execCmd "$FUNCNAME" "cp -r $INSTALLER_DIR/build/pnaf/bin $outdir"
    execCmd "$FUNCNAME" "touch    $PNAF_DIR/log/pool.capture"
    execCmd "$FUNCNAME" "touch    $PNAF_DIR/log/pool.audit"
    execCmd "$FUNCNAME" "rm -f    $PNAF_DIR/log/capture.fifo"
    execCmd "$FUNCNAME" "mkfifo   $PNAF_DIR/log/capture.fifo"
    execCmd "$FUNCNAME" "rm -f    $PNAF_DIR/log/audit.fifo"
    execCmd "$FUNCNAME" "mkfifo   $PNAF_DIR/log/audit.fifo"
    execCmd "$FUNCNAME" "mkdir -p $PNAF_DIR/log/capture"
    logMsg "$FUNCNAME" "Installing PNAF Perl API "
    execCmd "$FUNCNAME" "cd $INSTALLER_DIR/build/pnaf/Pnaf"
    execCmd "$FUNCNAME" "perl Makefile.PL"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    makeLinks
}
##############################################################################
installConfTemplates()
{
    local outdir="$PNAF_DIR/build/pnaf"
    logMsg "$FUNCNAME" "Installing configuration files templates"

    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/tmp/iprep/pnaf_blcat.dat\
			 $PNAF_DIR/etc/pnaf_blcat.dat"
    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/tmp/iprep/pnaf_blip.dat\
			 $PNAF_DIR/etc/pnaf_blip.dat"
    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/tmp/iprep/pnaf_bldn.dat\
			 $PNAF_DIR/etc/pnaf_bldn.dat"

    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/etc/template_snort.conf\
			 $PNAF_DIR/etc/snort.conf"
    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/etc/template_suricata.yaml\
			 $PNAF_DIR/etc/suricata.yaml"

    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/etc/template_emerging-dns.rules \
	     $PNAF_DIR/build/snort/rules/emerging-dns.rules "
    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/etc/template_emerging-attack_response.rules \
	     $PNAF_DIR/build/snort/rules/emerging-attack_response.rules "
    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/etc/template_emerging-current_events.rules \
	     $PNAF_DIR/build/snort/rules/emerging-current_events.rules"
    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/etc/template_emerging-policy.rules \
	     $PNAF_DIR/build/snort/rules/emerging-policy.rules"
    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/etc/template_emerging-worm.rules \
	     $PNAF_DIR/build/snort/rules/emerging-worm.rules"

    execCmd "$FUNCNAME" "cp $INSTALLER_DIR/build/pnaf/etc/template_httpd.conf \
	     $PNAF_DIR/build/httpd/conf/httpd.conf"
}
##############################################################################
installPkg()
{
    local fname="Pkg"
    perl -MCPAN -e 'my $c = "CPAN::HandleConfig"; $c->load(doit => 1, \
    autoconfig => 1); $c->edit(prerequisites_policy => "follow"); \
    $c->edit(build_requires_install_policy => "yes"); $c->commit'
    
    logMsg "$FUNCNAME" "Installing dependencies using (emerge/apt)"
    if [ "$1" == "debian" ]; then
	    execCmd "$FUNCNAME" "aptitude install -y autoconf automake \
	    binutils-dev bison \
	    build-essential byacc ccache cmake dsniff flex g++ gawk gcc \
	    libcap-ng-dev libcli-dev libdatetime-perl libdumbnet-dev \
	    libfixposix0 libfixposix-dev libgeoip-dev zlib1g zlib1g-dev \
	    libgetopt-long-descriptive-perl libglib2.0-cil-dev \
	    libjansson4 libjansson-dev libldns-dev liblzo2-2 libnet1-dev \
	    libmagic-dev libmysql++3 libmysqlclient-dev libmysql++-dev \
	    libnacl-dev libncurses5-dev libldns1 libnetfilter-conntrack-dev \
	    libnetfilter-queue1 libnetfilter-queue-dev libnet-pcap-perl \
	    libnfnetlink0 libnfnetlink-dev libnl-3-dev libnl-genl-3-dev \
	    libpcap-dev libpcre3 libpcre3-dbg libpcre3-dev libsqlite3-dev \
	    libssl-dev liburcu-dev libyaml-0-2 libyaml-dev liblzo2-dev \
	    openssl pkg-config python-dev python-docutils sqlite3 swig \
	    git-core libglib2.0-dev libtool tcpslice tcpick tshark \
	    tcpflow ethtool"
    elif [ "$1" == "gentoo" ]; then
        execCmd "$FUNCNAME" "emerge-webrsync"
        # Base packages    
        cmd="emerge --noreplace autoconf automake binutils bison libtool byacc\
	    ccache cmake flex gawk gcc dev-util/cmake sys-libs/libcap-ng\
	    dev-perl/glib-perl dev-libs/jansson dev-libs/lzo net-libs/libnet\
	    dev-libs/libnl virtual/perl-libnet dev-libs/geoip\
	    net-libs/libnetfilter_queue net-libs/libnetfilter_conntrack\
	    perl-core/libnet dev-perl/Net-PcapUtils dev-perl/Net-Pcap\
	    net-libs/libnfnetlink dev-db/sqlite dev-libs/libyaml\
	    dev-lang/swig net-analyzer/tcpflow dev-libs/libcli\
	    net-analyzer/dsniff dev-perl/DateTime ethtool"
        logMsg "$FUNCNAME" "Executing: $cmd"
        logMsg "$FUNCNAME" "See install.log.exec for detailed log ... (working)"
        eval "$cmd" &>> $INSTALLER_LOGFILE.exec
        if [ $? -ne 0 ]; then
	    logMsg "$FUNCNAME" "ERROR: Execution of ($cmd)"
	    exitInstall
        else
	    logMsg "$FUNCNAME" " $cmd ... OK"
        fi   
    fi    
}
##############################################################################
runInstaller()
{
    local fname="runInstaller-$1"
    tool=$1
    logMsg "$FUNCNAME" "Installing tool ($tool)"
    sleep 1
    case "$tool" in
	Tcpxtract)
	    installTcpxtract
	    ;;
	Yaf)
	    installYaf
	    ;;
	Ssldump)
	    installSsldump
	    ;;
	Dnsdump)
	    installDnsdump
	    ;;
	PassiveDNS)
	    installPassiveDNS
	    ;;
	Snort)
	    installSnort
	    ;;
	Httpd)
	    installHttpd
	    ;;
	Httpry)
	    installHttpry
	    ;;
	Xplico)
	    installXplico
	    ;;
	Cxtracker)
	    installCxtracker
	    ;;
	Chaosreader)
	    installChaosreader
	    ;;
	Suricata)
	    installSuricata
	    ;;
	IPforensics)
	    installIpforensics
	    ;;
	Tcpdump)
	    installTcpdump
	    ;;
	Netsniff)
	    installNetsniff
	    ;;
	Argus)
	    installArgus
	    ;;
	Dnscap)
	    installDnscap
	    ;;
	Prads)
	    installPrads
	    ;;
	Nftracker)
	    installNftracker
	    ;;
	P0f)
	    installP0f
	    ;;
	Barnyard)
	    installBarnyard
	    ;;
	Silk)
	    installSilk
	    ;;
	Tcpdstat)
	    installTcpdstat
	    ;;
	Tcpflow)
	    installTcpflow
	    ;;
	Bro)
	    installBro
	    ;;
	ConfTemplates)
	    installConfTemplates
	    ;;
	*)
	    logMsg "$FUNCNAME" "ERROR: Unknown tool $tool"
	    sleep 1
	    ;;
    esac
}
##############################################################################
makeLinks()
{
    local fname='makeLinks'
    logMsg "$FUNCNAME" "Installing binaries"
    cleanDir "$PNAF_DIR/bin"
    execCmd "$FUNCNAME" "mkdir -p $PNAF_DIR/bin"
    for i in `find $PNAF_DIR/build -name "*bin"`
    do
	local bins="`ls $i`"
    #	logMsg "$FUNCNAME" "Binaries from $i: $bins"
	for j in `ls $i`
	do
	    if [ -e $PNAF_DIR/bin/$j ]; then
		execCmd "$FUNCNAME" "rm -f $PNAF_DIR/bin/$j"
	    elif [ -L $PNAF_DIR/bin/$j ]; then
		execCmd "$FUNCNAME" "rm -f $PNAF_DIR/bin/$j"
	    fi
	    execCmd "$FUNCNAME" "ln -s $i/$j $PNAF_DIR/bin/$j"
        done
    done

    logMsg "$FUNCNAME" "Installing configuration files"
    for j in `find $PNAF_DIR/build -name "*.conf"`
    do
	local name=`echo $j | awk -F "/" '{print $NF}'`
	execCmd "$FUNCNAME" "rm -f $PNAF_DIR/etc/$name"
	execCmd "$FUNCNAME" "ln -s $j $PNAF_DIR/etc/$name"
    done

    logMsg "$FUNCNAME" "Updating environment vars"
    export PATH=$PNAF_DIR:$PATH
    installDir=`echo $PNAF_DIR/bin | sed 's/\//\\\\\//g'`
    execCmd "$FUNCNAME" "sed -i -r 's/:$installDir//g' /etc/profile"
    execCmd "$FUNCNAME" "sed -i -r 's/PATH=\"(.*)\"/PATH=\"\1:$installDir\"/' /etc/profile"
    execCmd "$FUNCNAME" "export PATH=$PNAF_DIR/bin:\$PATH"
    execCmd "$FUNCNAME" "source /etc/profile"
    execCmd "$FUNCNAME" "echo \"source /etc/profile\" >> ~/.bashrc"
}
##############################################################################
finalBanner()
{
    local fname="Message"
    banner="Passive Network Audit Framework v0.1 \
     has been installed successfully"
    logMsg "$FUNCNAME" "$banner"
}
##############################################################################
installTcpxtract()
{
    local tool="tcpxtract"
    local package=$TCPXTRACT
    local outdir="$PNAF_DIR/build/$tool"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "ldconfig"
}
##############################################################################
installYaf()
{
    local tool="yaf"

    local package="libfixbuf-1.4.0"
    local outdir="$PNAF_DIR/build/$tool"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "ldconfig"

    package=$YAF
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using source file $package.tar.gz"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/"
    cfgopt="--with-libpcap --enable-applabel --enable-plugins"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir $cfgopt"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "ldconfig"

    package="mysql-connector-c-6.1.3-linux-glibc2.5-x86_64"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using source file $package.tar.gz"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "/usr/local/mysql"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -xxvf $package.tar.gz"
    execCmd "$FUNCNAME" "mv $package /usr/local/mysql"

    package="yaf_silk_mysql_mediator-1.4.1"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using source file $package.tar.gz"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir\
	    --with-mysql=/usr/local/mysql/bin/mysql_config"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "ldconfig"
}
##############################################################################
installLibpcap()
{
    if [ -d "/usr/local/pcap" ] &&  [ -L "/usr/lib/libpcap.a" ]; then
        logMsg "$FUNCNAME" "LIBPCAP is already installed on the system"
        sleep 2
    else
        local tool="libpcap"
        local outdir="$PNAF_DIR/build/$tool"
        local package="$LIBPCAP"
        logMsg "$FUNCNAME" "Installing $package"
        logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
        execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
        cleanDir "$package"
        execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
        execCmd "$FUNCNAME" "cd $package"
        execCmd "$FUNCNAME" "./configure --prefix=/usr/local/pcap"
        execCmd "$FUNCNAME" "make"
        execCmd "$FUNCNAME" "make install"
        if [ -L /usr/local/include/net ]; then
            logMsg "$FUNCNAME" "Deleting existing link /usr/local/include/net"
            execCmd "$FUNCNAME" "rm /usr/local/include/net"
        fi
        execCmd "$FUNCNAME" "ln -s /usr/local/pcap/include/pcap /usr/local/include/net"
        if [ -L /usr/lib/libpcap.a ]; then
            logMsg "$FUNCNAME" "Deleting existing link /usr/lib/libpcap.a"
            execCmd "$FUNCNAME" "rm /usr/lib/libpcap.a"
        fi
        execCmd "$FUNCNAME" "ln -s /usr/local/pcap/lib/libpcap.a /usr/lib/libpcap.a"
        execCmd "$FUNCNAME" "ldconfig"
    fi
}
##############################################################################
installSsldump()
{
    installLibpcap
    local tool="ssldump"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$SSLDUMP"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    if [ "$OPT_OS" == "debian" ]; then                                
        cleanDir "$package"
	execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
	execCmd "$FUNCNAME" "cd $package"
        execCmd "$FUNCNAME" "./configure --prefix=$outdir"
    elif [ "$OPT_OS" == "gentoo" ]; then                              
        # Info on ebuild file from emerge
        # * Applying ssldump-0.9-libpcap-header.patch ...
        # * Applying ssldump-0.9-configure-dylib.patch ...
        # * Applying ssldump-0.9-openssl-0.9.8.compile-fix.patch ...
        # * Applying ssldump-0.9-DLT_LINUX_SLL.patch ...
        # * Applying ssldump-0.9-prefix-fix.patch ... 
        cleanDir "$package"
	execCmd "$FUNCNAME" "tar -zxvf $package-gentoo_patched.tar.gz"
	execCmd "$FUNCNAME" "cd $package"
        execCmd "$FUNCNAME" "./configure --prefix=$outdir\
		--with-pcap=/usr/local/pcap/ --build=x86_64-pc-linux-gnu\
		--host=x86_64-pc-linux-gnu"
    fi
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
}
##############################################################################
installDnsdump()
{
    installLibpcap
    local tool="dnsdump"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$DNSDUMP"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "mkdir -p $outdir/bin"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cp $package $outdir/bin/"
    logMsg "$FUNCNAME" "Installing CPAN modules dependencies..."
    execCmd "$FUNCNAME" "perl -MCPAN -e 'install Net::Packet'"
    execCmd "$FUNCNAME" "perl -MCPAN -e 'install Net::DNS'"
}
##############################################################################
installBro()
{
    installLibpcap
    local tool="bro"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$BRO"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
}
##############################################################################
installPassiveDNS()
{
    installLibpcap
    local tool="passivedns"
    local outdir="$PNAF_DIR/build/$tool"
    local package="ldns-1.6.17"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure --with-drill --disable-gost --disable-ecdsa"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "ldconfig"

    package="$PASSIVEDNS"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package/src"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    execCmd "$FUNCNAME" "cp -r $package/ $outdir"
    execCmd "$FUNCNAME" "mkdir -p $outdir/bin"
    execCmd "$FUNCNAME" "cp $outdir/src/passivedns $outdir/bin"
}
##############################################################################
installSnort()
{
    local tool="snort"
    local outdir="$PNAF_DIR/build/$tool"
    installLibpcap

    local package="libdnet-1.11"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $package source file $package.tar.gz"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    if [ "$OPT_OS" == "debian" ]; then                                
	    execCmd "$FUNCNAME" "./configure"
    elif [ "$OPT_OS" == "gentoo" ]; then                              
	    execCmd "$FUNCNAME" "./configure \"CFLAGS=-fPIC -g -O2\" "
    fi
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "ldconfig"

    local package="LuaJIT-2.0.2"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $package source file $package.tar.gz"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "ldconfig"

    local package="daq-2.0.4"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $package source file $package.tar.gz"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "ldconfig"

    local package="snort-2.9.7.0"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $package source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    cmd="./configure --prefix=$outdir --enable-sourcefire\
	 --enable-large-pcap --enable-file-inspect --enable-open-appid"
    execCmd "$FUNCNAME" "$cmd"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "mkdir $outdir/lib/snort_dynamicrules"
    execCmd "$FUNCNAME" "mkdir $outdir/etc"
    execCmd "$FUNCNAME" "cd etc"
    execCmd "$FUNCNAME" "cp attribute_table.dtd file_magic.conf snort.conf \
        unicode.map classification.config gen-msg.map reference.config \
        threshold.conf $outdir/etc"
    logMsg "$FUNCNAME" "Creating links on /usr/bin"
    execCmd "$FUNCNAME" "rm -rf /lib/libdnet.1"
    execCmd "$FUNCNAME" "ln -s /usr/local/lib/libdnet.1 /lib/"
    execCmd "$FUNCNAME" "rm -rf /usr/bin/u2openappid"
    execCmd "$FUNCNAME" "ln -s $outdir/bin/u2openappid /usr/bin"
	
    package="snort-openappid"
    logMsg "$FUNCNAME" "Configuring Snort OpenAppID"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "odp"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "mkdir $outdir/openappid/"
    execCmd "$FUNCNAME" "mv odp $outdir/openappid/"
    
    package="snortrules-snapshot-2970"
    logMsg "$FUNCNAME" "Installing VRT rules"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool/snort-rules/vrt/"
    cleanDir "$BUILD_DIR/$tool/snort-rules/vrt/rules"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "mv rules/ $outdir"
    execCmd "$FUNCNAME" "mv so_rules/ $outdir"
    execCmd "$FUNCNAME" "mv preproc_rules/ $outdir"
    execCmd "$FUNCNAME" "cp -r etc/* $outdir/etc"

    package="emerging.rules"
    logMsg "$FUNCNAME" "Installing ET rules"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool/snort-rules/et"
    cleanDir "$BUILD_DIR/$tool/snort-rules/et/rules"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "mv rules/* $outdir/rules"
    execCmd "$FUNCNAME" "cat $outdir/rules/sid-msg.map >> $outdir/etc/sid-msg.map"
    execCmd "$FUNCNAME" "cat $outdir/rules/gen-msg.map >> $outdir/etc/gen-msg.map"
    execCmd "$FUNCNAME" "cat $outdir/rules/classification.config >> \
	     $outdir/etc/classification.config"
    execCmd "$FUNCNAME" "touch $outdir/rules/white_list.rules"
    execCmd "$FUNCNAME" "touch $outdir/rules/black_list.rules"
    logMsg "$FUNCNAME" "Enabling ALL ruleset"
    for i in `ls $outdir/rules/*.rules`
    do
        execCmd "$FUNCNAME" "sed -i 's/^#alert/alert/g' $i"
	execCmd "$FUNCNAME" "sed -i 's/^##alert/alert/g' $i"
    done
    
    logMsg "$FUNCNAME" "Configuring $snortconf"
    snortconf="$outdir/etc/snort.conf"
    # Old variables
    orpath="var RULE_PATH"
    osrpath="var SO_RULE_PATH"
    oprpath="var PREPROC_RULE_PATH"
    owlpath="var WHITE_LIST_PATH"
    oblpath="var BLACK_LIST_PATH"
    olog="merged.log"
    class="classification.config"
    refer="reference.config"
    thres="threshold.conf"
    unico="unicode.map"
    outu2="output unified2: "
    rpath=`echo $outdir/rules          | sed 's/\//\\\\\//g'`
    srpath=`echo $outdir/so_rules      | sed 's/\//\\\\\//g'`
    prpath=`echo $outdir/preproc_rules | sed 's/\//\\\\\//g'`
    epath=`echo $outdir/etc/           | sed 's/\//\\\\\//g'`
    sdir=`echo $outdir/lib/            | sed 's/\//\\\\\//g'`
    logMsg "$FUNCNAME"  "Setting up snort.conf variables"
    execCmd "$FUNCNAME" "sed -i -r 's/($orpath) .*/\1 $rpath/'   $snortconf"
    execCmd "$FUNCNAME" "sed -i -r 's/($osrpath) .*/\1 $srpath/' $snortconf"
    execCmd "$FUNCNAME" "sed -i -r 's/($oprpath) .*/\1 $prpath/' $snortconf"
    execCmd "$FUNCNAME" "sed -i -r 's/($owlpath) .*/\1 $rpath/'  $snortconf"
    execCmd "$FUNCNAME" "sed -i -r 's/($oblpath) .*/\1 $rpath/'  $snortconf"
    execCmd "$FUNCNAME" "sed -i -r 's/($class)/ $epath\1/g'      $snortconf"
    execCmd "$FUNCNAME" "sed -i -r 's/($refer)/ $epath\1/g'      $snortconf"
    execCmd "$FUNCNAME" "sed -i -r 's/($thres)/ $epath\1/g'      $snortconf"
    execCmd "$FUNCNAME" "sed -i -r 's/ ($unico)/ $epath\1/g'     $snortconf"
    execCmd "$FUNCNAME" "sed -i -r 's/#.*($outu2.*)/\1/g'        $snortconf"
    execCmd "$FUNCNAME" "sed -i -r 's/\/usr\/local\/lib/$sdir/g' $snortconf"
    lnumber=`grep -n "Step #6: Configure output" $snortconf\
	 | awk -F ":" '{print $1 }'`
    inumber=`expr $lnumber - 2`
    logMsg "$FUNCNAME" "Adding openappid preprocessor conf on line $inumber"
    pline=" preprocessor appid : app_stats_filename appstats-unified.log,\
	  app_stats_period 60, app_detector_dir $outdir/openappid"
    execCmd "$FUNCNAME" "sed -i '$inumber i $pline'  $snortconf"
    nlogu2="snortIds.log"
    logcsv="output alert_csv: snort_csv.log"
    logMsg "$FUNCNAME" "Configuring output pluggin configuration"
    execCmd "$FUNCNAME" "sed -i -r 's/$olog/$nlogu2/g' $snortconf"
    lnumber=`grep -n "$outu2" $snortconf | awk -F ":" '{print $1 }'`
    inumber=`expr $lnumber + 2`
    execCmd "$FUNCNAME" "sed -i '$inumber i $logcsv'  $snortconf"

    logMsg "$FUNCNAME" "Creating configuration files links for Snort"
    execCmd "$FUNCNAME" "rm -f $PNAF_DIR/etc/classification.config"
    execCmd "$FUNCNAME" "ln -s $outdir/snort/etc/classification.config \
	                     $PNAF_DIR/etc/"
    execCmd "$FUNCNAME" "rm -f $PNAF_DIR/etc/gen-msg.map"
    execCmd "$FUNCNAME" "ln -s $outdir/snort/etc/gen-msg.map $PNAF_DIR/etc/"
    execCmd "$FUNCNAME" "rm -f $PNAF_DIR/etc/sid-msg.map"
    execCmd "$FUNCNAME" "ln -s $outdir/snort/etc/sid-msg.map $PNAF_DIR/etc/"
}
##############################################################################
installHttpd()
{
    local tool="httpd"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$HTTPD"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "rm -rf /etc/init.d/apache2"
    execCmd "$FUNCNAME" "ln -s $HTTPD_DIR/bin/apachectl /etc/init.d/apache2"
}
##############################################################################
installHttpry()
{
    local tool="httpry"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$HTTPRY"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "mkdir -p $outdir/bin"
    execCmd "$FUNCNAME" "mkdir -p /usr/man/man1/"
    installDir=`echo $outdir/bin | sed 's/\//\\\\\//g'`              
    logMsg "$FUNCNAME" "Installation dir $installDir on Makefile" 
    execCmd "$FUNCNAME" "sed -i -r 's/\/usr\/sbin/$installDir/' Makefile"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "cp -r scripts $outdir"
}
##############################################################################
installXplico()
{
    local tool="xplico"
    local outdir="$PNAF_DIR/build/$tool"
    cleanDir "$outdir"

    local package="$NDPI"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure"
    execCmd "$FUNCNAME" "make"

    package="$XPLICO"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    installDir=`echo $outdir | sed 's/\//\\\\\//g'`                       
    logMsg "$FUNCNAME" "Installation dir $installDir on Makefile"                  
    execCmd "$FUNCNAME" "sed -i -r 's/(DEFAULT_DIR) =.*/\1 = $installDir/' Makefile" 
    execCmd "$FUNCNAME" "make install"
    if [ -e /opt/xplico ]; then
        execCmd "$FUNCNAME" "rm /opt/xplico"
    elif [ -L /opt/xplico ]; then
	execCmd "$FUNCNAME" "rm /opt/xplico"
    fi
    execCmd "$FUNCNAME" "ln -s $outdir /opt/xplico"
}
##############################################################################
installCxtracker()
{
    local tool="cxtracker"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$CXTRACKER"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "mkdir -p $outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package/src"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "cp cxtracker ../bin"
    execCmd "$FUNCNAME" "cp -r ../../cxtracker/* $outdir"
    execCmd "$FUNCNAME" "chmod 755 $outdir/bin/*"
}
##############################################################################
installChaosreader()
{
    local tool="chaosreader"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$CHAOSREADER"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    execCmd "$FUNCNAME" "mkdir -p $outdir"
    execCmd "$FUNCNAME" "mkdir -p $outdir/bin"
    execCmd "$FUNCNAME" "cp $package $outdir/bin"
    execCmd "$FUNCNAME" "chmod 755 $outdir/bin/*"
}
##############################################################################
installSuricata()
{
    local tool="suricata"
    local outdir="$PNAF_DIR/build/$tool"
    installLibpcap
    local package="$SURICATA"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    if [ "$OPT_OS" == "gentoo" ]; then                              
	# Fix found on http://bit.ly/PKjojc
        execCmd "$FUNCNAME" "CPPFLAGS=-D_FORTIFY_SOURCE=2 ./configure \
		--prefix=$outdir --enable-geoip \
		--with-libjansson-includes=$SURICATA_LIBJANSSON_LIB \
		--with-libjansson-libraries=$SURICATA_LIBJANSSON_LIB"
    else                                
	execCmd "$FUNCNAME" "./configure --prefix=$outdir \
		--with-libjansson-includes=$SURICATA_LIBJANSSON_LIB \
		--with-libjansson-libraries=$SURICATA_LIBJANSSON_LIB \
		--enable-geoip"
    fi
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
    execCmd "$FUNCNAME" "make install-conf"
    execCmd "$FUNCNAME" "make install-rules"
    execCmd "$FUNCNAME" "cp $outdir/etc/suricata/rules/*map\
	     $outdir/etc/suricata"
    suriconf="$outdir/etc/suricata/suricata.yaml"
    execCmd "$FUNCNAME" "rm -f $PNAF_DIR/etc/suricata.yaml"
    execCmd "$FUNCNAME" "ln -s $suriconf $PNAF_DIR/etc/suricata.yaml"
}
##############################################################################
installIpforensics()
{
    local tool="ipforensics"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$IPFORENSICS"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "mkdir -p $outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME"  "mkdir -p $outdir"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "cp -r bin doc $outdir"
}
##############################################################################
installTcpdump()
{
    installLibpcap
    local tool="tcpdump"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$TCPDUMP"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
}
##############################################################################
installNetsniff()
{
    if [ "$OPT_OS" == "debian"]; then
        installLibpcap
        local tool="netsniff"
        local outdir="$PNAF_DIR/build/$tool"
        local package="$NETSNIFF"
        logMsg "$FUNCNAME" "Installing $package"
        logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
        cleanDir "$outdir"
        execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
        cleanDir "$package"
        execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
        execCmd "$FUNCNAME" "cd $package"
        execCmd "$FUNCNAME"  "mkdir -p $outdir/sbin/"
        execCmd "$FUNCNAME"  "mkdir -p $outdir/share/man/man8/"
        installDir=`echo $outdir | sed 's/\//\\\\\//g'`              
        logMsg "$FUNCNAME" "Installation dir $installDir on Makefile" 
        execCmd "$FUNCNAME" "./configure"
        execCmd "$FUNCNAME" "sed -i -r 's/(PREFIX) \?=.*/\1 \?= $installDir/' Makefile"
        execCmd "$FUNCNAME" "make"
        execCmd "$FUNCNAME" "make install"
    fi
}
##############################################################################
installArgus()
{
    installLibpcap
    local tool="argus"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$ARGUS_SERVER"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"

    package="$ARGUS_CLIENT"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
}
##############################################################################
installDnscap()
{
    installLibpcap
    local tool="dnscap"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$DNSCAP"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
}
##############################################################################
installPrads()
{
    installLibpcap
    local tool="prads"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$PRADS"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    installDir=`echo $outdir | sed 's/\//\\\\\//g'`              
    logMsg "$FUNCNAME" "Installation dir $installDir on Makefile" 
    execCmd "$FUNCNAME" "sed -i -r 's/(PREFIX)=.*/\1=\"$installDir\"/' Makefile"
    execCmd "$FUNCNAME" "make"
    if [ "$OPT_OS" == "gentoo" ]; then
	execCmd "$FUNCNAME" "sed -i -e '/MAN/Id' Makefile"
        execCmd "$FUNCNAME" "sed -i -e '/DOC/Id' Makefile"
    fi
    execCmd "$FUNCNAME" "make install"

    logMsg "$FUNCNAME" "Creating configuration files links for PRADS"
    pradsconf="$outdir/etc/prads"
    for j in `ls $pradsconf| grep -v init.d`
    do
	execCmd "$FUNCNAME" "rm -f $PNAF_DIR/etc/$j"
	execCmd "$FUNCNAME" "ln -s $pradsconf/$j $PNAF_DIR/etc/$j"
    done
}
##############################################################################
installNftracker()
{
    installLibpcap
    local tool="nftracker"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$NFTRACKER"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package/src"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "cp -r ../../nftracker $outdir"
    execCmd "$FUNCNAME" "mkdir $outdir/bin/"
    execCmd "$FUNCNAME" "mv $outdir/src/nftracker $outdir/bin/" 
}
##############################################################################
installP0f()
{
    installLibpcap
    local tool="p0f"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$P0F"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    logMsg "$FUNCNAME" "Compiling with SSL support"
    logMsg "$FUNCNAME" "Reference: http://bit.ly/1hkSmFM"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "mkdir -p $outdir/bin"
    execCmd "$FUNCNAME" "mkdir -p $outdir/src"
    execCmd "$FUNCNAME" "cp -r * $outdir/src"    
    execCmd "$FUNCNAME" "cp $outdir/src/p0f $outdir/bin"
    execCmd "$FUNCNAME" "cp $outdir/src/p0f.fp $outdir/"
    execCmd "$FUNCNAME" "rm -f $PNAF_DIR/etc/p0f.fp"
    execCmd "$FUNCNAME" "ln -s $outdir/p0f.fp $PNAF_DIR/etc/p0f.fp"
}
##############################################################################
installBarnyard()
{
    local tool="barnyard"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$BARNYARD"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./autogen.sh"
    execCmd "$FUNCNAME" "./autogen.sh"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
}
##############################################################################
installSilk()
{
    installLibpcap
    local tool="silk"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$SILK"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
}
##############################################################################
installTcpdstat()
{
    installLibpcap
    local tool="tcpdstat"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$TCPDSTAT"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "mkdir -p $outdir/bin"
    installDir=`echo $outdir | sed 's/\//\\\\\//g'`              
    logMsg "$FUNCNAME" "Installation dir $installDir on Makefile" 
    execCmd "$FUNCNAME" "sed -i -r 's/(PREFIX)=.*/\1=\"$installDir\"/' Makefile"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
}
##############################################################################
installTcpflow()
{
    installLibpcap
    local tool="tcpflow"
    local outdir="$PNAF_DIR/build/$tool"
    local package="$TCPFLOW"
    logMsg "$FUNCNAME" "Installing $package"
    logMsg "$FUNCNAME" "Using $tool source file $package.tar.gz"
    cleanDir "$outdir"
    execCmd "$FUNCNAME" "cd $BUILD_DIR/$tool"
    cleanDir "$package"
    execCmd "$FUNCNAME" "tar -zxvf $package.tar.gz"
    execCmd "$FUNCNAME" "cd $package"
    execCmd "$FUNCNAME" "./configure --prefix=$outdir"
    execCmd "$FUNCNAME" "make"
    execCmd "$FUNCNAME" "make install"
}
##############################################################################
##############################################################################
##############################################################################
start
