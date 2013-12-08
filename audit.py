#!/usr/bin/python
"""
NAME: audit.py
DESC: Generate a Red Hat Gap Analysis Report based on CIS standards
DATE: 02 Jul 2013
AUTHOR: Gene Ordanza <geronimo.ordanza@fisglobal.com>
TODO: 1. Set the SELinux Policy
      2. Check for Unconfined Daemons
"""

import os
import sys
from sys import stdout
import subprocess as sp
from auditlib import Item
from auditlib import Item as k
from optparse import OptionParser

(ENABLE, DISABLE, DONE, FAILED) = (1, 0, 'DONE', 'FAILED')
SUCCESS, ERROR = 0, 1

# ------  Function For Parsing Command Line Args  ------

def main():

    if cmdparser():
        header()
        osrelease()

    parser = OptionParser(description=Item.desc, usage=Item.usage,
                          version=Item.version)

    parser.add_option('-i', '--inst', default=False, action='store_true',
                      dest='inst', help=Item.header10)

    parser.add_option('-k', '--kerpa', default=False, action='store_true',
                      dest='kern', help=Item.header40)

    parser.add_option('-l', '--lgcpkg', default=False, action='store_true',
                      dest='pkg', help=Item.header20)

    parser.add_option('-o', '--spack', default=False, action='store_true',
                      dest='spck', help=Item.header30)

    parser.add_option('-s', '--sshcfg', default=False, action='store_true',
                      dest='ssh', help=Item.header60)

    parser.add_option('-y', '--usrenv', default=False, action='store_true',
                      dest='usrv', help=Item.header70)

    parser.add_option('-u', '--usrgrp', default=False, action='store_true',
                      dest='usr', help=Item.usrgrp)


# ========================================================================


    (opts, args) = parser.parse_args()

    if opts.inst: checkupdtptchsec(Item.header10)
    if opts.pkg:  legacypackage(Item.header20)
    if opts.spck: checkspepack(Item.header30)
    if opts.kern: checkkerpara(Item.header40)

    if opts.ssh:  sysaccauth(Item.header60)
    if opts.usrv: checkuserenv(Item.header70)
    if opts.usr: systemmain(Item.header90)

# -------------------------------------------------

# Check if user passed --version or --help
def cmdparser():
    val = True
    num = len(sys.argv)

    if len(sys.argv) == 1: val = False
    if num > 1 and sys.argv[1] == '--version': val = False
    if num > 1 and sys.argv[1] == '--help':    val = False
    if num > 1 and sys.argv[1] == '-h':        val = False

    return val


# ======  Helper Functions  ======

# Decorator function to modify runtime behavior; mostly use for header message
# boilerplace code.
def headerdecorator(func):
    def wrapper(*args):
        print Item.frmt1 % ('', args[0])
        func(*args)
    return wrapper

def footdecorator(func):
    def wrapper(*args):
        result = func(*args)
        print result
        if type(result) is list:
            print Item.frmt5 % ('', args[1], ' '.join(result[1:]))
        else:
            print Item.frmt5 % ('', args[1], result)

    return wrapper

# Check if file exist; if not, exit program
def filecheck(filelist):
    retval = 0
    for x in filelist:
        if not os.path.exists(x):
            print '\tERROR: %s does not exist!' % x
            retval = 1

    if retval:
        print Item.skipmodtest
#       sys.exit(1)

    return


# Get the return value of the command; valt "value true"; valf "value false"
def retvalue(command, valt='turn-on', valf='turn-off'):
    child = sp.Popen(command, stdout=sp.PIPE, stderr=stdout.fileno(), shell=True)
    retcode = child.communicate()[0]
    return int(child.returncode)


# Run native commands
def runcommand(command):
    result = sp.Popen(command, stdout=sp.PIPE, shell=True)
    (output, err) = result.communicate()
    return output


# Display if particular value/setting is ENABLED or NOT SET
def valdisplay(val, msg, switchon='ENABLED', switchoff='NOT SET'):

    if val: print Item.frmt2 % ('', msg, switchon)
    else:   print Item.frmt2 % ('', msg, switchoff)


# Display result of chkconfig command
def chkconfigdsply(name, result):
    if type(result) is list:
        print Item.frmt5 % ('', name, ' '.join(result[1:]))
    else:
        print Item.frmt5 % ('', name, result)


# Run chkconfig for a given service and return output in a list
def chkcfgservice(msg, service):
    print Item.frmt1 % ('', msg)

    cmd = '/sbin/chkconfig --list %s' % service
    return runcommand(cmd).strip().split()


def chkconfig(service):
    cmd = k.chkconfig + service
    if retvalue(cmd) == ERROR:
        return 'service not available'
    return runcommand(cmd).strip().split()


# Run ls command to retrieve permission and user/group owner
def lscommand(filename):

    if not os.path.exists(filename):
        return ['', '', 'not', 'found', filename]
    cmd  = k.lsld + filename
    return runcommand(cmd).split()


# Display result of ls command
def lsdisplay(str1):
    owner = '%s/%s' % (str1[2], str1[3])
    print Item.frmt3 % ('', str1[-1], owner, str1[0])

# Display kernel parameters
def sysctl2(kpara):

    for x in kpara:
        val = runcommand(k.sysctl+x).strip().split('=')
        valdisplay(True, val[0], val[1])


def systemfile(setting, filecnf):
    val = False

    if filecheck([filecnf]) == 1:
        valdisplay(0, setting, DONE, FAILED)

    cmd = k.plaingrepcmd + setting + filecnf

    if retvalue(cmd) == SUCCESS:
        val = True

    valdisplay(val, setting, 'INCLUDED', 'NOT SET')

# File Configuration parser
def configparser(filep, setting, sep=None):

    var = False
    filep.seek(0)

    for x in filep:
        line = x.strip().split(sep)
        if line and line[0] == setting:
            var = True
            valdisplay(True, setting, line[1])

    if not var:
        valdisplay(var, setting, 'NOT SET')

# Check rpm package
def checkrpmpack(package):

    val = False
    cmd = k.rpmq + package
    if retvalue(cmd) == SUCCESS:
        val = True
    valdisplay(val, package, '  INSTALLED', 'UNINSTALLED')


# quick hack - retrieve a pattern from a string (need to refactor)
def groupid(str1, num):
    return str1.strip().split(':')[num]


# Display headers
def header():
    print Item.title
    print Item.hostname
    print Item.datetoday



# ------  Main subroutines ------

# Check the current RHEL version on the server
def osrelease():
    print Item.checkosver

    try:
        fp = open(Item.rhel)
        print '\t%s' % fp.read().strip()
    except IOError:
        print Item.frmt2 % ('', Item.rhelerror1, '')
        print Item.frmt2 % ('', Item.rhelerror2, '')
        sys.exit(1)


# ===== 1.x INSTALL UPDATES, PATCHES, AND ADDITIONAL SECURITY SOFTWARE ====

# 1.1.1 Check filesystem mount options
def fsoption(dir, option):
    title = "%s %s option in %s filesystem" % (Item.fsoption, option, dir)
    print Item.frmt1 % ('', title)
    fsoptmsg = '%s option' % option

    val, tmp = False, Item.tempfile
    cmd = 'mount > %s' % tmp
    runcommand(cmd)

    filep = open(tmp)

    for x in filep:
        if x.find(dir) >= 0 and x.find(option) >= 0:
            val = True

    valdisplay(val, fsoptmsg)
    filep.close()


# 1.1.2 Find all World-Writable directories
@headerdecorator
def stckybit(msg):

    print Item.frmt2 % ('', 'Searching ...', '')
    str1 = runcommand(k.findwwdir).strip().split()

    for x in str1:
        runcommand(Item.wwdirfile % x)

    valdisplay(True, 'output written to world-writable-dir.txt', '')


# 1.3.2 Check if Red Hat GPG Key is Installed
@headerdecorator
def fingerp(*args):

    runcommand(k.gpgcheck)

    val, filep = False, open(k.tempfile)

    for x in filep:
        y = x.strip().split()
        if y and y[0] == 'Key' and y[1] == 'fingerprint':
            genkey = x.split('=')[-1].replace(' ','').strip()
            if genkey == Item.rhnkey:
                valdisplay(True, Item.validkeymsg, 'VALID')
            else:
                valdisplay(True, Item.validkeymsg, 'INVALID')

    filep.close()


# 1.3.3 Verify that gpgcheck is Globally Activated
@headerdecorator
def gpgcheck(*args):

    val = False

    for x in args[1]:
        y = x.strip().split('=')
        if y and y[0] == 'gpgcheck' and int(y[-1]) == 1:
            val = True

    valdisplay(val, Item.glbltrue, 'ACTIVATED', 'DEACTIVATED')


# 1.3.4-5 Check for the rhnsd and yum-updatesd Daemon
@headerdecorator
def rhnsdaemon(*args):

    chkconfigdsply(args[1], chkconfig(args[1]))


# 1.3.7 Check package integrity using RPM
@headerdecorator
def verifypack(*args):

    valdisplay(True, 'Searching ...', '')
    valdisplay(True, 'TODO Item. Temporarily run (manually) this audit.', '')
#   runcommand(Item.rpmvcheck)

#   filep = open(tmp)
#   filep = open(Item.tempfile)
#   for x in filep:
#       y = x.strip().split()
#       if y[1] != 'c':
#           print Item.frmt3 % ('', y[0], y[1], '')

#   filep.close()


# 1.5.1 Check SELinux settings in /etc/grub.conf
@headerdecorator
def selnxgrub(*args):

    (val, command) = True, Item.grepcmd

    for x in command:
        if retvalue(x) == SUCCESS:
            val = False

    valdisplay(val, 'SELinux in grub.conf')

# 1.5.2 Check SELinux settings in /etc/selinux/config
@headerdecorator
def seconfig(*args):

    filep = open(args[1])

    configparser(filep, 'SELINUX', '=')
    configparser(filep, 'SELINUXTYPE', '=')

    filep.close()

# 1.5.2 Check if SELinux is enabled at boot time
@headerdecorator
def selnxstate(*args):
    (temp, cmd) = Item.tempfile, Item.sestatuscmd

    runcommand(cmd)

    filep = open(temp)
    for x in filep:
        y = x.replace(' ', '').strip().split(':')
        valdisplay(True, y[0], y[1])

    filep.close()


# 1.5.5 Check if setroubleshoot/mcstrans service is running
@headerdecorator
def seservice(*args):

    chkconfigdsply(args[1], chkconfig(args[1]))
    chkconfigdsply(args[2], chkconfig(args[2]))

# 1.6.1 Check owner and permission of grub.conf
@headerdecorator
def grubperm(*args):

    lsdisplay(lscommand(Item.grubconf))

# 1.6.3 Check if boot loader password is set
@headerdecorator
def bootsettings(*args):

    systemfile(args[1], args[2])

# 1.7.1 Check if XD/NX Kernel Support is Enable
def xdnxcheck(x):
    checkrpmpack(x)

# ------  Subroutine for checkupdtptchsec functions ------

# 1.6.5 Disable Interactive Boot
@headerdecorator
def interactboot(*args):

    filecheck([args[1]])

    filep = open(args[1])

    configparser(filep, k.prompt, '=')

    filep.close()

# 1.1 Check Filesystem Configuration
@headerdecorator
def checkfsconfig(msg):

    fsoption('/tmp', 'nodev')
    fsoption('/tmp', 'nosuid')
    fsoption('/tmp', 'noexec')
    fsoption('/home', 'nodev')
    fsoption('/dev/shm', 'nodev')
    fsoption('/dev/shm', 'nosuid')
    fsoption('/dev/shm', 'noexec')
    stckybit(Item.stckybit)

# 1.3 Configure Software Updates
@headerdecorator
def checkrhn(*args):

    filecheck([Item.yumfile])
    yumfile = open(Item.yumfile)

    fingerp(Item.header132)
    gpgcheck(Item.header133, yumfile)
    rhnsdaemon(Item.header134, 'rhnsd')
    rhnsdaemon(Item.header135, 'yum-updatesd')
    verifypack(Item.header137)

    yumfile.close()


# 1.5 Check SELinux Configuration
@headerdecorator
def checkselinux(*args):

    selnxgrub(Item.header151)
    seconfig(Item.header152, k.selinuxcfg)
    selnxstate(Item.header153)
    seservice(Item.header154, k.setrouble, k.semcstrans)


# 1.6 Check Secure Boot Settings
@headerdecorator
def checkgrub(*args):

    grubperm(Item.header161)
    bootsettings(Item.header162, k.grubpass, k.grubconf)
    bootsettings(Item.header163, k.singleuser, k.inittab)
    interactboot(Item.header165, k.initfile)

# 1.7 Additional Process Hardening
@headerdecorator
def prcshardening(*arg):

    filecheck([Item.plink])

    filep = open(Item.plink)

    sysctl2(k.suid_dumpable)
    sysctl2(k.execshield)
    sysctl2(k.randomize_va)
    xdnxcheck(k.kernel)
    configparser(filep, 'PRELINKING', '=')

    filep.close()


# 1.0 Install Updates, Patches, And Additional Security Software
@headerdecorator
def checkupdtptchsec(*args):

    checkfsconfig(Item.header11)
    checkrhn(Item.header13)
    checkselinux(Item.header15)
    checkgrub(Item.header16)
    prcshardening(Item.header17)


# ===== 2.x OS SERVICES =====

# 2.1 Check for Legacy Services
def legacyprogram():

    for x in Item.legacypack:
        checkrpmpack(x)

# 2.2 Check for Xinetd Services
def xinetservices():

    print
    for x in Item.xinetd:
        chkconfigdsply(x, chkconfig(x))

# 2.0 Check if legacy packages is installed and legacy services is turn on
@headerdecorator
def legacypackage(*args):

    legacyprogram()
    xinetservices()

# ===== 3.x SPECIAL PURPOSE SERVICES =====

# 3.3.1 Check Avahi Server Settings
@headerdecorator
def avahiset(*args):

    filecheck([args[1]])

    filep = open(args[1])
    for setting in args[2]:
        configparser(filep, setting, '=')

    filep.close()

# 3.8 Check NFS and RPC Server
@headerdecorator
def nfsrpc(*args):

    for x in args[1]:
        chkconfigdsply(x, chkconfig(x))

# 3.5, 3.7 Checking RPM Package: dhcp, ldap
@headerdecorator
def rpmpackage(*args):
    checkrpmpack(args[1])

# 3.3, 3.4 Check Avahi Server, CUPS Printer
@headerdecorator
def configlist(*args):
    chkconfigdsply(args[1], chkconfig(args[1]))

# 3.2 Check X Windows Runlevel
@headerdecorator
def xrunlevel(*args):

    result = runcommand(k.grepid).strip().split(':')
    valdisplay(True, 'Runlevel', result[1])

# 3.1 Check Daemon Umask
@headerdecorator
def daemonumask(*args):

    result = runcommand(args[1]).strip().split()
    if result and result[0].upper() == 'UMASK':
        valdisplay(True, 'UMASK', result[1])
    else:
        valdisplay(True, 'UMASK', 'NOT SET')


# 3.0 Check Special Purpose Services
@headerdecorator
def checkspepack(*args):

    daemonumask(Item.header31, k.grepmask)
    xrunlevel(Item.header32)
    configlist(Item.header33, 'avahi-daemon')
    avahiset(Item.header331, k.avahiconf, k.avahiset)
    configlist(Item.header34, 'cups')
    rpmpackage(Item.header35, 'dhcp')
#   ntpd(Item.header36, 'ntp')  # TODO Later
    rpmpackage(Item.header37, 'openldap-servers')
    nfsrpc(Item.header38, Item.nfsservice)
    rpmpackage(Item.header39, 'bind')
    rpmpackage(Item.header341, 'vsftpd')
    rpmpackage(Item.header342, 'httpd')
    rpmpackage(Item.header343, 'dovecot')
    rpmpackage(Item.header344, 'samba')
    rpmpackage(Item.header345, 'squid')
    rpmpackage(Item.header346, 'net-snmp')


# ===== 4.x NETWORK CONFIGURATION AND FIREWALL ====

# 4.1 Display Network Parameters (Host Only)
@headerdecorator
def hostonly(*args):

    sysctl2(k.ip_forward)
    sysctl2(k.send_redirects)

# 4.2 Display Network Parameters (Host and Router)
@headerdecorator
def hostrouter(*args):

    sysctl2(k.accept_source_route)
    sysctl2(k.accept_redirects)
    sysctl2(k.secure_redirects)
    sysctl2(k.log_martians)
    sysctl2(k.ignore_broadcast)
    sysctl2(k.bogus_error)
    sysctl2(k.rp_filter)
    sysctl2(k.tcp_syncookies)

# 4.3 Deactivate Wireless Interfaces - Not Applicable

# 4.4 Disable IPV6
@headerdecorator
def disableipv6(*args):

    systemfile(k.optionv6, k.modprob)
    sysctl2(k.accept_ra)
    sysctl2(k.accept_redirects6)


# 4.5 Check TCP Wrappers Permission
@headerdecorator
def tcpwrapper(*args):

    filelist = [Item.hostallow, Item.hostdeny]

    filecheck(filelist)

    for x in filelist:
        lsdisplay(lscommand(x))

# 4.6-7 Enable IPtables and IP6tables
@headerdecorator
def iptables(*args):

    chkconfigdsply(args[1], chkconfig(args[1]))

# 4.8 Disable Uncommon Network Protocols
@headerdecorator
def ucprotocol(msg):

    systemfile(k.dccp, k.modprob)
    systemfile(k.sctp, k.modprob)
    systemfile(k.rds,  k.modprob)
    systemfile(k.tipc, k.modprob)


# 4.0 Network Configuration and Firewall Subroutine
@headerdecorator
def checkkerpara(msg):

    hostonly(Item.header41)
    hostrouter(Item.header42)
    disableipv6(Item.header44)
    tcpwrapper(Item.header45)
    iptables(Item.header46, k.iptables4)
    iptables(Item.header47, k.iptables6)
    ucprotocol(Item.header48)

# ===== 6.x SYSTEM ACCESS, AUTHENTICATION AND AUTHORIZATION =====

# Check PAM Configuration
@headerdecorator
def checkpam(*args):
    print '(TOBE IMPLEMENTED on 3rd pass of Ceridian Hardening Project)'

# ------  SSH Configuration Subroutines ------

# 6.2.1 Check permission of sshd_config file
@headerdecorator
def sshperm(*args):

    lsdisplay(lscommand(Item.sshfile))


# 6.2.2 Check settings of sshd_config file
@headerdecorator
def sshset(*args):

    filecheck([Item.sshfile])

    try:
        sshfp = open(Item.sshfile)

        for x in k.sshpara:
            configparser(sshfp, x)

    finally:
        sshfp.close()

# 6.2 Check SSH Configuration Settings
@headerdecorator
def checksshcfg(*args):

    sshperm(Item.header621)
    sshset(Item.header622)


# 6.1.1 Check crond and anacron services
def crondanac():
    for (x, y) in k.cronserv:
        configlist(x, y)

# 6.1.2 Check crontab files
def crontabfiles():

    print
    for x in k.cronfiles:
        lsdisplay(lscommand(x))

    print
    for x in Item.cronperm:
        lsdisplay(lscommand(x))

# 6.1 Check configuration/permission for cron and anacron
@headerdecorator
def checkcron(*args):

    crondanac()
    crontabfiles()


# 6.0 System Access, Authentication and Authorization
@headerdecorator
def sysaccauth(*args):

    checkcron(Item.header61)
    checksshcfg(Item.header62)
    checkpam(Item.header63)

# ===== 7.x USER ACCOUNTS AND ENVIRONMENT =====

# 7.1 Display System Accounts that hasn't been set to 'nologin' or 'false' shell
@headerdecorator
def disableaccts(*args):

    val = True
    args[1].seek(0)

    for x in args[1]:
        str1  = x.strip().split(':')
        shell = str1[-1].split('/')[-1]
        if int(str1[2]) < 500 and shell != 'nologin' and shell != 'false':
            valdisplay(True, str1[0], shell)
            val = False

    if val:
        valdisplay(True, 'All System Accounts are Disable', '')


# 7.2 Set Shadow Password Suite Parameters (/etc/login.defs)
@headerdecorator
def loginpara(*args):

    args[1].seek(0)

    for x in args[1]:
        y = x.strip().split()
        if y and y[0] == 'PASS_MAX_DAYS': valdisplay(True, y[0], y[1])
        if y and y[0] == 'PASS_MIN_DAYS': valdisplay(True, y[0], y[1])
        if y and y[0] == 'PASS_MIN_LEN':  valdisplay(True, y[0], y[1])
        if y and y[0] == 'PASS_WARN_AGE': valdisplay(True, y[0], y[1])


# 7.3 Display Default Group for root Account
@headerdecorator
def rootgroup(*args):

    str1  = runcommand('id root').strip().split()
    str2  = str1[-1].split('=')
    group = str2[-1].split(',')
    for x in group: valdisplay(True, x, '')


# 7.4 Display Default User Umask Settings
@headerdecorator
def usermask(*args):

    args[1].seek(0)

    for x in args[1]:
        str1 = x.strip().split()
        if str1 and str1[0].upper() == 'UMASK':
            valdisplay(True, str1[0], str1[1])


# 7.0  User Accounts and Environment
@headerdecorator
def checkuserenv(*args):

    filecheck(Item.useraccenvfiles)

    try:
        passwd, profile = open(Item.passwd), open(Item.profile)
        logindef        = open(Item.logindef)

        disableaccts(Item.header71, passwd)
        loginpara(Item.header72, logindef)
        rootgroup(Item.header73)
        usermask(Item.header74, profile)

    finally:
        passwd.close(); profile.close(); logindef.close()

# ===== 9.x SYSTEM MAINTENANCE =====

# 9.1.1 Verify System File Permissions
@headerdecorator
def systemfiles(*args):

    filecheck(args[1])

    for x in args[1]:
        lsdisplay(lscommand(x))

# 9.1.9 Find World Writable Files
@headerdecorator
def specfiles(*args):

    print Item.frmt2 % ('', 'Searching ...', '')
    str1 = runcommand(args[1]).strip().split()

    for x in str1:
        runcommand(Item.output % (x, args[2]))

    valdisplay(True, k.outmesg + args[2], '')


# 9.2.1 Verify password fields are not empty
@headerdecorator
def passempty(*args):

    val = 1
    for x in args[1]:
        str1 = x.split(':')
        if str1[1] == '':
            msg = '%s password field empty' % str1[0]; val = 0
            valdisplay(True, msg, '')
    if val:
        valdisplay(True, 'No empty password field found!', '')

    args[1].seek(0)

# 9.2.2 Verify No Legacy "+" Entries Exist in /etc/{passwd,shadow,group} File
@headerdecorator
def legacyplus(*args):

    val = 1
    for x in args[1]:
        if x.find('+') >= 0:
            str1 = x.split(':')
            msg = "%s legacy user found!" % str1[0] ; val = 0
            valdisplay(True, msg, '')
    if val:
        valdisplay(True, 'No Legacy Entries Found!', '')

    args[1].seek(0)


# 9.2.5 Verify No UID 0 Account Exist Other Than root
@headerdecorator
def rootuid(*args):

    val = 1
    for x in args[1]:
        str1 = x.split(':')
        if int(str1[2]) == 0:
            msg = '%s user has UID 0!' % str1[0] ; val = 0
            valdisplay(True, msg, '')
    if val:
        valdisplay(True, 'No UID 0 found other than root', '')

    args[1].seek(0)

# 9.2.6 rootpath()

# 9.2.7 Verify User Home Directory Permission
@headerdecorator
def homeperm(*args):

    for x in args[1]:
        str1 = x.split(':')
        if int(str1[2]) >= 500:
            lsdisplay(lscommand(str1[5]))

    args[1].seek(0)


# 9.2.9 Verify Permission of User .netrc Files
@headerdecorator
def findfile(*args):

    output = runcommand(args[1]).split()

    for x in output:
        lsdisplay(lscommand(x))

    if not output:
        valdisplay(True, args[2] + ' not found', '')

# 9.2.11 Check for groups defined in /etc/passwd file but not in /etc/group
# TODO: Need to clean-up this function
@headerdecorator
def findgrpdup(*args):

    filep, fileg = open(Item.passwd), open(Item.group)

    found = True
    for x in filep:
        val = True
        passgroup = groupid(x, 3)

        for y in fileg:
            if groupid(x, 3) == groupid(y, 2):
                val = False

        if val:
            output = '%s is not defined in group file' % passgroup
            valdisplay(True, output, '')
            found = False

        fileg.seek(0)

    if found:
        valdisplay(True,'all groups in /etc/passwd are defined in /etc/group', '')

    filep.close(), fileg.close()



# 9.2.15 Verify That No Duplicate ID/Group exists
#def findiddup(filep, msg, field=0):
@headerdecorator
def findiddup(*args):

    uid   = {}
    field = args[2]

    for x in args[1]:
        line = x.split(':')
        uid[line[field]] = 0

    args[1].seek(0)

    for x in args[1]:
        line = x.split(':')
        if line[field] in uid:
            uid[line[field]] += 1

    val = True
    for key in uid:
        if uid[key] > 1:
            str1 = '\"%s\" is duplicate UID/GID account' % (key)
            print Item.frmt2 % ('', str1, '')
            val = False

    if val:
        valdisplay(True, 'No duplicate UID/GID found', '')
    args[1].seek(0)


# 9.2 Review User and Group Settings
@headerdecorator
def checkugsettings(*args):

    filecheck(k.systemfiles)

    try:
        passwd, group   = open(Item.passwd), open(Item.group)
        shadow, gshadow = open(Item.shadow), open(Item.gshadow)

        passempty(Item.header921, passwd)   # Check empty password field
        legacyplus(Item.header922, passwd)  # Check for "+" in /etc/passwd
        legacyplus(Item.header923, shadow)  # Check for "+" in /etc/shadow
        legacyplus(Item.header924, group)   # Check for "+" in /etc/shadow
        rootuid(Item.header925, passwd)     # Check for duplicate 0 UID

        # TODO: rootpath()
        homeperm(Item.header927, passwd)       # Display homedir permissions
        findfile(Item.header928, k.fnetrc, '.netrc')
        findfile(Item.header929, k.frhost, '.rhosts')

        findgrpdup(Item.header9211)

        findiddup(Item.header9215, passwd, 2)     # Find Duplicate UID
        findiddup(Item.dupgidmsg, group, 2)     # Find Duplicate GID
        findiddup(Item.dupnamemsg, passwd, 0)   # Find Duplicate Username
        findiddup(Item.dupgrpmsg,  group, 0)     # Find Duplicate Groupname

    finally:
        passwd.close(); shadow.close(); group.close()


# 9.1 Check World-Writable Files, No-owners, and  SUID/GUID Files
@headerdecorator
def checkfileperm(*args):

    systemfiles(Item.header911, k.systemfiles)
    specfiles(Item.header919, k.fwwcom, k.fwwfile)
    specfiles(Item.header9110, k.fnouse, k.fnofile)
    specfiles(Item.header9112, k.fsuid,  k.fsufile)
    specfiles(Item.header9113, k.fsgid,  k.fsgfile)


# 9.0 System Maintenance
@headerdecorator
def systemmain(*args):

    checkfileperm(Item.checkfileperm)
    checkugsettings(Item.header92)

if  __name__ == '__main__':
    main()

