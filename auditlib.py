#!/usr/bin/python
"""
NAME: auditlib.py
DESC: Generate a Red Hat Gap Analysis Report based on CIS standards
DATE: 21 May 2013
REPO: https://urldefense.proofpoint.com/v1/url?u=http://www.github.com/geneordanza/&k=%2FbkpAUdJWZuiTILCq%2FFnQg%3D%3D%0A&r=cTwVJqBqD3OycVGb10fGZoa6DfElSsezLjy8tnWk7x4%3D%0A&m=yR8BUPFsj6i6m%2FR%2FlDE444gsw%2F3l0%2FlFrIJEl4WeAkk%3D%0A&s=6264fd59561ba019019c175180ed442aa8a2d0d7f8aa377dd35e955c68168c20
AUTHOR: Gene Ordanza <geronimo.ordanza@fisglobal.com>
"""

import socket
import platform
from datetime import datetime

class Item(object):

    # Print format
    frmt1 = '\n%4s %-25s'
#   frmt2 = '%10s %-25s %s'
#   frmt2 = '%7s %-38s %10s'
    frmt2 = '%7s %-45s %10s'
    frmt3 = '%7s %-28s %-15s %10s'
    frmt4 = '%10s %-25s %-20s'
    frmt5 = '%7s %-18s %38s'

    # Display Headers
    title = '\n%40s\n%40s' % ('FIS AUDIT REPORT', '='*16)
    hostname = '\nHostname: %s' % socket.gethostname().upper()
    datetoday = 'Date    : %s\n' % str(datetime.now()).split()[0]

    # Display Subroutine Headers

    checkosver  = 'Checking version of installed Red Hat Enterprise Linux:'
    checkrhn    = '\nChecking for RHN Software Configuration:'
#   checkcron   = '\nChecking Cron and Anacron Setup:'
    checkuserenv  = '\n>> Check User Accounts and Environments:'

    # RHEL Information File
    rhel = '/etc/redhat-release'
    rhelerror1 = 'ERROR: This is a %s %s platform!' % \
                 (platform.dist()[0], platform.dist()[1])
    rhelerror2 = 'This audit program is meant for RHEL 5/6 release'

    # Display help strings for OptionParser Subroutine
    desc    = 'The audit.py utility generate a security audit based on FIS \
               standards.'
    usage   = '%prog [options]'
    version = '%prog v1.0'

    fscfg   = 'Check File System Configuration'
    selx    = 'Check SELinux Configuration'
    grub    = 'Check Secure Boot Setting'
    tcpwrp  = 'Check TCP Wrappers files and permissions'
    wrldsgid= 'Check for world-writable files, suid/sgid, and system \
               files (passwd/shadow/group/gshadow)'
    ccron   = 'Check Cron and Anacron setup'
    rhnsetp = 'Check RHN RPM Repositories'
    usrgrp  = 'Check User and Group Settings for duplicate UID/GID, Legacy \
             \"+\" accounts, duplicate UID 0, empty password field, and look \
             for .netrc and .rhosts files'

    # Display for RHN Configuration
    gpgkey      = '* Checking for Red Hat GPG Key...'
    validkeymsg = 'Red Hat Signing Key'
    tempfile    = '/tmp/tempfile'

    globalgpg = '* Checking If gpgcheck Settings (Global) Is Activated...'
    glbltrue  = 'gpgcheck option'

#   yumfile = '/etc/yum.conf'
#   gpgfile = '/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release'

    yumfile = '/home/gene/Workarea/Hardening/yum.conf'
    gpgfile = '/etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6'

    rhnkey      = 'C1DAC52D1664E8A4386DBA430946FCA2C105B9DE'    # CENTOS
#   rhnkey      = '47DB287789B21722B6D95DDE5326810137017186'    # RHEL

    rhnsdmn     = '* Checking If rhnsd Daemon Is Enabled...'
    yumudmn     = '* Checking If yum-updatesd Daemon Is Enabled...'

    vrfypack    = '* Checking Packages That Has Been Modified... ' + \
                  '(might take few minutes)'




    # Error message when file is not found
    skipmodtest = '\tskipping this module test ...'

    # variable definition to be use in fileperm module
    wworldmsg = ['\n\tLooking for root-owned world writable files ... ',
                 '\tNo world writable files found.']

    nousermsg = ['\n\tLooking for unowned files and directories ...',
                 '\tNo unowned files or directories found']

    suidmsg   = ['\n\tLooking for SUID files ...',
                 '\tNo SUID files found']

    sgidmsg   = ['\n\tLooking for SGID files ...',
                 '\tNo SGID files found']


    # File definition for TCP Wrappers
    hostallow = '/etc/hosts.allow'
    hostdeny  = '/etc/hosts.deny'


    # File Definition for checksshcfg Subroutine
    sshfile = '/etc/ssh/sshd_config'
#   sshfile = '/home/gene/Workarea/Hardening/sshd_config'

    sshprtomsg = '* Checking SSH Protocol Setting ...'
    sshllvlmsg = '* Checking SSH Loglevel Setting ...'
    sshx11msg  = '* Checking SSH X11 Forwarding Setting ...'
    sshmaxmsg  = '* Checking SSH Max Authentication Tries ...'
    sshignrmsg = '* Checking SSH IgnoreRhost Settings ...'
    sshauthmsg = '* Checking SSH Hostbased Authentication ...'
    sshrootlogmsg  = '* Checking SSH Root Login Authentication ...'
    sshemptypasmsg = '* Checking SSH Permit Empty Password ...'
    sshciphermsg   = '* Checking SSH Approved Ciphers in Counter Mode ...'
    sshintervalmsg = '* Checking SSH Set Idle Timeout Interval for User ...'
    sshbannermsg   = '* Checking SSH Banner Settings ...'


    # File Definition for checkuserenv Subroutine

    # File Definition for checkugsettings Subroutine
#   passwd  = '/home/gene/Workarea/Hardening/password'
#   group   = '/home/gene/Workarea/Hardening/group'
#   shadow  = '/home/gene/Workarea/Hardening/shadow'
#   gshadow = '/home/gene/Workarea/Hardening/gshadow'

    passwd    = '/etc/passwd'
    group     = '/etc/group'
    shadow    = '/etc/shadow'
    gshadow   = '/etc/gshadow'

    gruplegmsg = "\t* Checking for Legacy \"+\" Entries Exist in /etc/group File ..."
    netrcmsg   = "\t* Checking for .netrc Permissions"
    rhostmsg   = "\t* Checking for .rhosts Permissions"

    dupidmsg   = "Checking for Duplicate UID"
    dupgidmsg  = "Checking for Duplicate GID"
    dupnamemsg = "Checking for Duplicate Usernames"
    dupgrpmsg  = "Checking for Duplicate Names"


# ===== 1.0 INSTALL UPDATES, PATCHES, AND ADDITIONAL SECURITY SOFTWARE ====

    header10    = "Check for Install Updates, Patches, " + \
                  "And Additional Security Software"
    header11    = "\n* File System Configuration:"
    header15    = "\n* SELinux Configuration:"
    header151   = "Checking SELinux in /etc/grub.conf Settings ..."
    header152   = "Checking /etc/selinux/config Settings"
    header153   = "Checking SELinux State at Boot Time"
    header154   = "Checking SELinux Service Runlevel"
    header16    = "\n* Secure Boot Settings:"
    header161   = 'Checking User/Group Ownership and Permission of grub.conf'
    header162   = 'Checking Grub Boot Loader Password'
    header163   = 'Checking Authentication for Single-User Mode'
    header165   = 'Checking Interactive Boot'
    header17    = "\n* Additional Process Hardening"


    # Display for File System Configuration
    fsoption    = 'Checking for'
    stckybit    = 'Checking for World-Writable Directories'

    findwwdir   = "find / -path /proc -prune -o " + \
                  " -type d \( -perm -0002 -a ! -perm 1000 \) -print"

    # find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print0 |
    # xargs -0 chmod +t

    wwdirfile   = 'echo %s >> world-writable-dir.txt'
    plaingrepcmd= 'grep '

    # ---- 1.5 Configure SELinux ----
    grep1       = 'grep enforcing=0 /etc/grub.conf'
    grep2       = 'grep selinux=0   /etc/grub.conf'
    grepcmd     = [grep1, grep2]

    sestatuscmd = '/usr/sbin/sestatus > %s' % tempfile

    setrouble   = 'setroubleshoot'
    semcstrans  = 'mcstrans'

    selinuxcfg  = '/etc/selinux/config'

    # ---- 1.6 Secure Boot Settings
    grubconf    = '/boot/grub/grub.conf'
    grubpass    = 'password '

    inittab     = '/etc/inittab'
    singleuser  = 'sulogin '

    initfile    = '/etc/sysconfig/init'
    prompt      = 'PROMPT'

    # ---- 1.7 Additional Process Hardening ----

    suid_dumpable = ['fs.suid_dumpable']
    execshield    = ['kernel.exec-shield']
    randomize_va  = ['kernel.randomize_va_space']
    kernel        = 'kernel-PAE'
    plink         = '/etc/sysconfig/prelink'

# ===== 2.0 OS SERVICES ======

    header20 = "Check for OS Services and Legacy Packages"
    legacypack = ['telnet-server', 'telnet', 'rsh-server', 'rsh', 'yp-tools',
                  'yp-bind', 'ypserv', 'tftp', 'tftp-server', 'talk',
                  'openssl', 'talk-server', 'xinetd']

    xinetd = ['chargen-dgram', 'chargen-stream', 'daytime-dgram',
              'daytime-stream', 'echo-dgram', 'echo-stream', 'tcpmux-server',
              'gene-service']

    rpmq = 'rpm -q '

# ===== 3.0 SPECIAL PURPOSE SERVICES =====

    header30 = "Check for Special Purpose Services"
    header31 = "Checking Daemon Umask:"
    header32 = "Checking RunLevel:"
    header33 = "Checking Avahi Server:"
    header331 = "Checking Settings for Avahi Server:"
    header34 = "Checking CUPS Print Server:"
    header35 = "Checking DHCP Server:"
    header36 = "Checking NTP Server:"
    header37 = "Checking LDAP Server:"
    header38 = "Checking NFS and RPC:"
    header39 = "Checking DNS Server:"
    header341 = "Checking FTP Server:"
    header342 = "Checking HTTP Server:"
    header343 = "Checking Dovecot Server:"
    header344 = "Checking Samba Server:"
    header345 = "Checking HTTP Proxy Server:"
    header346 = "Checking SNMP Server:"

    sysinit     = '/etc/sysconfig/init'
    avahiconf   = '/etc/avahi/avahi-daemon.conf'
    grepid      = 'grep id: /etc/inittab'
    grepmask    = 'grep -i umask /etc/sysconfig/init'
    nfsservice  = ['nfslock', 'rpcgssd', 'rpcidmapd', 'portmap']


    services = ['avahi-daemon', 'ntpd', 'nfs', 'sendmail']

    avahiset = ['use-ipv6', 'use-ipv4', 'check-response-ttl',
                'disallow-other-stacks', 'disable-publishing',
                'publish-address', 'publish-binfo',
                'publish-workstation', 'publish-domain']

# ===== 4.0 NETWORK CONFIGURATION AND FIREWALL ====

    header40 = "Check Kernel (Network) Parameters and Configuration " + \
               "and Firewall"

    header41    = '* Network Parameters (Host Only)'
    header42    = '* Network Parameters (Host and Router)'
    header44    = '* Disable IPV6'
    header45    = '* TCP Wrapper Permissions:'
    header46    = '* Enable IPtables'
    header47    = '* Enable IP6tables'
    header48    = '* Disable Uncommon Network Protocols'

    netv4   = 'net.ipv4.'
    netv4a  = 'net.ipv4.conf.all.'
    netv4c  = 'net.ipv4.conf.'
    netv4d  = 'net.ipv4.conf.default.'
    netv6c  = 'net.ipv6.conf.default.'
    sysctl  = '/sbin/sysctl '
    chkconfig = '/sbin/chkconfig --list '
    modprob = '/etc/modprobe.conf-delete'

    # ---- Network Parameters (Host Only) ----
    ip_forward = [netv4 + 'ip_forward']
    send_redirects = [netv4a + 'send_redirects', netv4d + 'send_redirects']

    # ---- Network Parameters (Host and Routers) ----
    accept_source_route = [netv4a + 'accept_source_route',
                           netv4d + 'accept_source_route']
    accept_redirects    = [netv4a + 'accept_redirects',
                           netv4d + 'accept_redirects']
    secure_redirects    = [netv4a + 'secure_redirects',
                           netv4d + 'secure_redirects']
    log_martians        = [netv4a + 'log_martians']
    ignore_broadcast    = [netv4  + 'icmp_echo_ignore_broadcasts']
    bogus_error         = [netv4  + 'icmp_ignore_bogus_error_responses']
    rp_filter           = [netv4a + 'rp_filter',
                           netv4d + 'rp_filter']
    tcp_syncookies      = [netv4  + 'tcp_syncookies']

    # ---- Disable IPV6 ----
    optionv6            = '\"options ipv6\" '

    accept_ra           = [netv6c + 'accept_ra']
    accept_redirects6   = [netv6c + 'accept_redirects']

    # ---- Enable IPtables ----
    iptables4   = 'iptables'
    iptables6   = 'ip6tables'

    # ---- Disable Uncommon Network Protocols ----
    dccp        = '\"install dccp\" '
    sctp        = '\"install sctp\" '
    rds         = '\"install rds\" '
    tipc        = '\"install tipc\" '


# ===== 6.x SYSTEM ACCESS, AUTHENTICATION AND AUTHORIZATION =====

    header60    = "Check System Access, Authentication and Authorization"
    header61    = "\n* Checking Cron and Anacron Setup:"
    header611   = "Checking anacron Service"
    header612   = "Checking crond Service"
    header62    = "\n* Checking SSH Configuration Settings:"
    header621   = "Checking sshd_config file permission"
    header622   = "Checking sshd_config parameters"
    header63    = "\n* Checking PAM Configuration"

#   sshcfg  = 'Check SSH configuration settings'

    lsld        = 'ls -ld '
    sshpara     = ['Protocol',  # Set to 2
                  'LogLevel',   # Set to VERBOSE
                  'X11Forwarding',  # Set to No
                  'MaxAuthTries',   # Set to 4
                  'IgnoreRhosts',   # Set to Yes
                  'HostbasedAuthentication',    # Set to No
                  'PermitRootLogin',            # Set to No
                  'PermitEmptyPasswords',       # Set to No
                  'PermitUserEnvironment',      # Set to No
                  'Ciphers',        # Use Ciphers in Counter Mode
                  'ClientAliveInterval',        # Set to 300
                  'ClientAliveCountMax',        # Set to 0
                  'Banner' ]

    cronserv    = [[header611, 'anacron'],
                   [header612, 'crond']]

    # File definition for checkcron subroutine (cron/anacron)
    canacron = 'cronie-anacron'
    crond   = 'crond'

    anacron = '/etc/anacrontab'
    crontab = '/etc/crontab'
    chourly = '/etc/cron.hourly'
    cdaily  = '/etc/cron.daily'
    cweekly = '/etc/cron.weekly'
    cmonthly = '/etc/cron.monthly'
    ccrond  = '/etc/cron.d'

    cronfiles = [anacron, crontab, chourly, cdaily, cweekly, cmonthly, ccrond]

    cronallow = '/etc/cron.allow'
    crondeny  = '/etc/cron.deny'
    atallow   = '/etc/at.allow'
    atdeny    = '/etc/at.deny'

    cronperm   = (cronallow, crondeny, atallow, atdeny)

# ===== 7.0 USER ACCOUNTS AND ENVIRONMENT =====

    header70    = "Check User Accounts and Environment"
    header71    = '\n* Checking System Account That Have Shell'

    header72    = '\n* Checking Password Expiration, Minimum Days ' + \
                  'for Change, Expiry Warning Days'

    header73    = '\n* Checking Default Group for root Account'
    header74    = '\n* Checking Default Umask for Users'
    logindef    = '/etc/login.defs'

    useraccenvfiles = [passwd, logindef]

# ===== 9.0 SYSTEM MAINTENANCE =====
    header90    = "Check System Maintenance"
    header911   = "Verify System File Permissions"
    header919   = "Find World Writable Files"
    header9110  = "Find Un-owned and Un-grouped Files and Directories"
    header9111  = "Find Un-grouped Files and Directories"
    header9112  = "Find SUID System Executables"
    header9113  = "Find SGID System Executables"

    header92    = "\n* Check User and Group Settings"
    header921   = "Checking for any empty password field"
    header922   = 'Check for Legacy "+" Entries in /etc/passwd'
    header923   = 'Check for Legacy "+" Entries in /etc/shadow'
    header924   = 'Check for Legacy "+" Entries in /etc/group'
    header925   = 'Check for UID 0 Account Other Than root'
    header927   = 'Check for User Home Directory Permission'
    header928   = 'Check for .netrc file Permission'
    header929   = 'Check for .rhosts file Permission'

    header9210   = "\t* Checking for Duplicate UID"

#   netrcmsg   = "\t* Checking for .netrc Permissions"
#   homepermsg = "\t* Checking for User Home Directory Permission"
#   rootuidmsg = "\t* Checking for UID 0 Accounts Other Than root"

    systemmain  = "\nVerify System File Permissions"

    checkfileperm = '\n* Check System File Permissions:'

    output      = 'echo %s >> %s'
    outmesg     = 'output written to '

    fwwcom = 'find / -path /proc -prune -o -type f -user root -perm /o=w'
    fwwfile= 'world-writable-files.txt'

    fnouse = 'find / -path /proc -prune -o -type f \( -nouser -o -nogroup \)'
    fnofile = 'unowned-ungroup-files.txt'

    fsuid  = 'find / -path /proc -prune -o -perm -4000'
    fsufile= 'suid-files.txt'

    fsgid  = 'find / -path /proc -prune -o -perm -2000'
    fsgfile= 'sgid-files.txt'

    fnetrc = 'find /home -iname .netrc'
    frhost = 'find /home -iname .rhosts'

    nofilefnd  = '--- No \"%s\" file found ---'

    systemfiles = [passwd, shadow, gshadow, group]

Documentation = """
This is documentation. To be edited.
"""
