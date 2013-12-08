#!/bin/bash
# DESC: (limited) application of recommended hardening settings from CIS Security
#       Configuration Benchmark (RHEL5 servers).  These configuration is targeted
#       for the following servers:
#       - stp1domprod1
#       - stp1domprod2
#       - stp1domhub1
# NOTES:
#       - The processHardening module causes Lotus Notes to behave erratically.
#       - The kernelsetting module is also applicable to eReports and SeeMyW2
#         servers with minimal change.
# AUTHOR : Gene Ordanza II <geronimo.ordanza@fisglobal.com>
# VERSION: 20130920


timestamp=$(date '+%Y%m%d')

# Configuration files
declare -a configfiles=('/etc/fstab'
                        '/etc/sysconfig/prelink'
                        '/etc/sysconfig/init'
                        '/etc/avahi/avahi-daemon.conf'
                        '/etc/ntp.conf'
                        '/etc/sysctl.conf'
                        '/etc/modprobe.conf'
                        '/etc/audit/audit.rules'
                        '/etc/ssh/sshd_config'
                        '/etc/pam.d/su'
                        '/etc/profile'
                        '/etc/security/limits.conf'
                        '/usr/share/gdm/themes/RHEL/RHEL.xml')

declare -a fstabcfg=('/\<tmp\>/s/defaults/defaults,nodev,nosuid,noexec/'
                     '/\<shm\>/s/defaults/defaults,nodev,nosuid,noexec/'
                     '/\<home\>/s/defaults/defaults,nodev/')

declare -a kernelcfg=('# *** Ceridian Hardening Settings *** '
                      'net.ipv4.conf.all.send_redirects = 0'
                      'net.ipv4.conf.default.send_redirects = 0'
                      'net.ipv4.conf.all.accept_redirects = 0'
                      'net.ipv4.conf.default.accept_redirects = 0'
                      'net.ipv4.conf.all.secure_redirects = 0'
                      'net.ipv4.conf.default.secure_redirects = 0'
                      'net.ipv4.conf.all.log_martians = 1'
                      'net.ipv4.conf.all.rp_filter = 1'
                      'net.ipv4.conf.default.rp_filter = 1'
                      'net.ipv6.conf.default.accept_ra = 0'
                      'net.ipv6.conf.default.accept_redirects = 0')

declare  -a avahicfg=('/^use-ipv4/s/yes/no/'
                      '/^use-ipv6/s/yes/no/'
                      '/^#check-response-ttl/s/yes/no/'
                      's/^#check-response-ttl/check-response-ttl/'
                      '/^#disallow-other-stacks/s/no/yes/'
                      's/^#disallow-other-stacks/disallow-other-stacks/'
                      '/^#disable-publishing/s/no/yes/'
                      's/^#disable-publishing/disable-publishing/'
                      '/^#publish-addresses/s/yes/no/'
                      's/^#publish-addresses/publish-addresses/'
                      '/^#publish-hinfo/s/yes/no/'
                      's/^#publish-hinfo/publish-hinfo/'
                      '/^#publish-workstation/s/yes/no/'
                      's/^#publish-workstation/publish-workstation/'
                      '/^#publish-domain/s/yes/no/'
                      's/^#publish-domain/publish-domain/')


declare -a cronfiles=('/etc/anacrontab'
                      '/etc/crontab'
                      '/etc/cron.hourly'
                      '/etc/cron.daily'
                      '/etc/cron.weekly'
                      '/etc/cron.monthly')


declare -a sshconfig=('# **Ceridian Settings **'
                      'LogLevel Verbose'
                      'X11Forwarding no'
                      'MaxAuthTries 4'
                      'IgnoreRhosts yes'
                      'HostbasedAuthentication no'
                      'PermitEmptyPasswords no'
                      'PermitUserEnvironment no')

# Config file modifier
function sedder {
    sed -i "$2" $3
#   if [ "$1" = "insert" ]; then
#       sed -i "$2" $3
#   elif [ "$1" = "append" ]; then
#       echo "hello $1"
#   elif [ "$1" = "sub" ]; then
#       echo "hello $1"
#   fi
}

# Backup configuration files
function filebackup {
    echo -e "\nBackup Configuration Files"
    for cfg in "${configfiles[@]}"; do
        echo -e "  $cfg ..."
        cp -p $cfg $cfg-orig-${timestamp}
    done

    find /etc -iname '*-orig-*'
#   find /etc -iname '*-orig-20130902' -print0 | xargs -0 rm -f
}


function crondir {
    echo -e "\nChanging Permission of Cron files/directories"

    for arg in "${cronfiles[@]}"; do
        chmod og-rwx $arg
        ls -ld $arg
    done

    rm -rf /etc/at.deny  /etc/cron.deny
    touch  /etc/at.allow /etc/cron.allow
    chmod  og-rwx /etc/at.allow /etc/cron.allow
}

# Mount /dev/shm /tmp /home with recommended mount options
function filesysconfig {
  b="/tmp             /var/tmp        none    bind        0 0"
  echo "Filesystem Configuration"

# echo " Initial mount configuration: "
# mount | grep -i 'home\|shm\|\<tmp\>'

  for arg in /dev/shm /tmp; do
    mount -o remount,nodev,nosuid,noexec $arg
  done

  mount -o remount,nodev /home
  echo " Mount configuration after remount: "
  mount | grep -i nodev

  for arg in "${fstabcfg[@]}"; do
      sedder insert "$arg" ${configfiles[0]}
  done

  mount --bind /tmp /var/tmp
  sed -i "$ a $b" ${configfiles[0]}
}

function processHardening {
    sed -i "$ a * hard core 0" ${configfiles[11]}
    sed -i "$ a fs.suid.dumpable = 0" ${configfiles[5]}
    sed -i "$ a kernel.exec-shield = 1" ${configfiles[5]}
    sed -i "$ a kernel.randomize_va_space = 1" ${configfiles[5]}
}


function modprobeconfig {
    for arg in dccp sctp rds tipc; do
        sedder insert "$ a install $arg /bin/true" ${configfiles[6]}
    done
}

# SSH server configuration
function sshdconfig {
    echo "Changing ${configfiles[8]} file ..."
    chmod 644 ${configfiles[8]}
    for arg in "${sshconfig[@]}"; do
        sedder insert "$ a $arg" ${configfiles[8]}
    done
}

# Avahi configuration (disabled by default)
function avahicnf  {
    echo "Changing ${configfiles[3]} file ..."
    for arg in "${avahicfg[@]}"; do
        sedder insert "$arg" ${configfiles[3]}
    done
}

# Kernel parameters
function kernelsetting {
    echo "Changing ${configfiles[5]} ..."
    for arg in "${kernelcfg[@]}"; do
        sedder insert  "$ a $arg" ${configfiles[5]}
    done
#   sysctl -p
}

# Miscellaneous one-liner stuff
function oneliner {
    echo 'test'
    for arg in auditd anacron; do
        chkconfig $arg on
    done

    sed -i "/^PRELINKING/s/yes/no/" ${configfiles[1]}
    sed -i "$ a umask 027" ${configfiles[2]}
    sed -i "6 s/^#//" ${configfiles[9]}
    sed -i "$ a umask 022" ${configfiles[10]}

    cp -p /etc/issue /etc/issue.net
    useradd -D -f 60
}

# SELinux configuration
function selinuxconfig {
    for arg in setroubleshoot mcstrans; do
        chkconfig $arg off
    done
}

function main {
    echo 'Ceridian Hardening Settings for STP servers'
#   filebackup
#   filesysconfig
#   processHardening
#   selinuxconfig
#   avahicnf
#   kernelsetting
#   modprobeconfig
#   crondir
#   sshdconfig
#   oneliner
}

main
