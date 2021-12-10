## This class implements STIG controls for a RHEL 8 Server.
## This implementation assumes that you are working with a minimimal
## install of RHEL8 and does not account for any applications / use 
## cases for the OS.  It's simply designed to have the highest possible
## compliance score for the OS, to have a "secure" baseline upon which
## to build applications.
class rhel8_stig {
# run exec only if command in onlyif returns 0.
  exec { 'verify_fips_mode':
    command => '/bin/fips-mode-setup --enable',
    onlyif  => '/bin/grep 0 /proc/sys/crypto/fips_enabled',
  }

  package { 'vlock':
      ensure => present,
  }

  package { 'tmux':
      ensure => present,
  }

  file { 'tmux_config':
    path    => '/etc/tmux.conf',
    mode    => '0644',
    source  => 'puppet:///modules/rhel8_stig/tmux.conf',
    require => Package['tmux'],
  }

  file_line { 'fix_tmux_entry':
    ensure            => absent,
    path              => '/etc/shells',
    match             => '^.*tmux$',
    match_for_absence => true,
    multiple          => true,
  }

  package { lookup('mandatory_packages'):
      ensure => present,
  }


  package { 'rng-tools':
      ensure => present,
  }

  service { 'rngd':
    ensure  => running,
    enable  => true,
    require => Package['rng-tools'],
  }

  service { 'systemd-coredump.socket':
    ensure => stopped,
    enable => mask,
  }

  service { 'ctrl-alt-del.target':
    ensure => stopped,
    enable => mask,
  }

  service { 'debug-shell.service':
    ensure => stopped,
    enable => mask,
  }

  package { 'openssh-server':
    ensure => present,
  }

  service { 'sshd':
    ensure  => running,
    enable  => true,
    require => Package['openssh-server'],
  }

  package { 'rsyslog':
    ensure => present,
  }

  service { 'rsyslog':
    ensure  => running,
    enable  => true,
    require => Package['rsyslog'],
  }

file { '/etc/rsyslog.conf':
      ensure  => file,
      mode    => '0644',
      source  => 'puppet:///modules/rhel8_stig/rsyslog.conf',
      require => Package['rsyslog'],
  }

  package { 'audit':
    ensure => present,
  }

service { 'auditd.service':
    ensure  => running,
    enable  => true,
    require => Package['audit']
  }

  package { 'firewalld':
    ensure => present;
  }

  file_line { 'firewalld_backend':
    path  => '/etc/firewalld/firewalld.conf',
    line  => 'FirewallBackend=nftables',
    match => '^FirewallBackend=',
  }

  service { 'firewalld.service':
    ensure  => running,
    enable  => true,
    require => Package['firewalld']
  }

  package { 'fapolicyd':
    ensure => present;
  }

  service { 'fapolicyd.service':
    ensure  => running,
    enable  => true,
    require => Package['fapolicyd'],
  }

package { 'usbguard':
    ensure => present;
  }

  service { 'usbguard.service':
    ensure  => running,
    enable  => true,
    require => Package['usbguard'],
  }

  package { lookup('disallowed_packages'):
    ensure => absent,
  }

package { lookup('abrt_packages'):
    ensure => absent,
  }

  file { '/etc/pam_pkcs11':
      ensure  => directory,
      mode    => '0755',
      require => Package['openssl-pkcs11'],
  }

  file { '/etc/pam_pkcs11/pam_pkcs11.conf':
      ensure  => file,
      mode    => '0644',
      source  => 'puppet:///modules/rhel8_stig/login.defs',
      require => Package['openssl-pkcs11'],
  }

  file { '/etc/ssh/sshd_config':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/sshd_config',
  }

  file { '/etc/issue':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/issue',
  }

  file { '/etc/login.defs':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/login.defs',
  }

  file { '/usr/share/crypto-policies/DEFAULT/opensshserver.txt':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/crypto_opensshserver.config',
  }

  file { '/etc/crypto-policies/back-ends/opensshserver.txt':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/crypto_opensshserver.config',
  }

  file { '/etc/bashrc':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/bashrc',
  }

  file { '/var/log/messages':
    ensure => file,
    mode   => '0640',
    owner  => 'root',
    group  => 'root',
  }

  file { '/var/log':
  ensure => directory,
  mode   => '0755',
  owner  => 'root',
  group  => 'root',
}

file { '/var/log/audit/audit.log':
    ensure => file,
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }

  file { '/var/log/audit':
    ensure => directory,
    mode   => '0700',
    owner  => 'root',
    group  => 'root',
  }

  file { '/etc/audit/auditd.conf':
    ensure => file,
    mode   => '0640',
    owner  => 'root',
    group  => 'root',
    source => 'puppet:///modules/rhel8_stig/auditd.conf',
  }

  file { '/etc/security/pwquality.conf':
    ensure => file,
    mode   => '0644',
    owner  => 'root',
    group  => 'root',
    source => 'puppet:///modules/rhel8_stig/pwquality.conf',
  }

file { '/etc/ssh/ssh_host_ed25519_key':
    ensure => file,
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }

  file { '/etc/ssh/ssh_host_ecdsa_key':
    ensure => file,
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }

  file { '/etc/ssh/ssh_host_rsa_key':
    ensure => file,
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }

  file { '/etc/security/limits.conf':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/limits.conf',
  }

  file { '/etc/sysctl.d/99-sysctl.conf':
      ensure => file,
      mode   => '0644',
      owner  => 'root',
      group  => 'root',
      source => 'puppet:///modules/rhel8_stig/99-sysctl.conf',
  }

  file { '/etc/sudoers.d/99-sudoers.conf':
      ensure => file,
      mode   => '0644',
      owner  => 'root',
      group  => 'root',
      source => 'puppet:///modules/rhel8_stig/99-sudoers.conf',
  }

  file { '/etc/security/faillock.conf':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/faillock.conf',
  }

  kernel_parameter { 'page_posion':
    ensure => present,
    value  => '1',
  }

  kernel_parameter { 'vsyscall':
    ensure => present,
    value  => 'none',
  }

  kernel_parameter { 'slub_debug':
    ensure => present,
    value  => 'P',
  }

  kernel_parameter { 'audit':
    ensure => present,
    value  => '1',
  }

  kernel_parameter { 'audit_backlog_limit':
    ensure => present,
    value  => '8192',
  }

  kernel_parameter { 'pti':
    ensure => present,
    value  => 'on',
  }

#   #grub_user { 'root':
#   #  password    => 'Temp1234!',
#   #  superuser   => true,
#   #  before      => Exec['update-grub'],
#   #}

#   #exec { 'update-grub':
#   #  command => '/usr/sbin/update-grub',
#   #  onlyif => '/bin/grep -i password /boot/grub/grub.cfg'
#   #}

  file_line { 'secure_rescue_mode':
    path  => '/usr/lib/systemd/system/rescue.service',
    line  => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue',
    match => '^ExecStart=',
  }

  file_line { 'secure_emergency_mode':
    path  => '/usr/lib/systemd/system/emergency.service',
    line  => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency',
    match => '^ExecStart=',
  }

  file_line { 'selinux_mode':
    path  => '/etc/selinux/config',
    line  => 'SELINUX=enforcing',
    match => '^SELINUX=',
  }

  file_line { 'selinux_type':
    path  => '/etc/selinux/config',
    line  => 'SELINUXTYPE=targeted',
    match => '^SELINUXTYPE=',
  }

  file_line { 'tls_min_level':
    path  => '//etc/crypto-policies/back-ends/opensslcnf.config',
    line  => 'TLS.MinProtocol = TLSv1.2',
    match => '^TLS.MinProtocol',
  }

file_line { 'min_level':
    path => '//etc/crypto-policies/back-ends/opensslcnf.config',
    line => 'MinProtocol = TLSv1.2',
  }

  # file_line { 'sssd_ocsp_dgst':
  #   path  => '/etc/sssd/sssd.conf',
  #   line  => 'certificate_verification = ocsp_dgst=sha1',
  #   match => '^certificate_verification',
  # }

  file_line { 'ssh_strong_rng':
    path  => '/etc/sysconfig/sshd',
    line  => 'SSH_USE_STRONG_RNG=32',
    match => '^SSH_USE_STRONG_RNG=',
  }

file_line { 'dnf_local_pkg_gpgcheck':
    path  => '/etc/dnf/dnf.conf',
    line  => 'localpkg_gpgcheck=True',
    match => '^localpkg_gpgcheck=',
  }

file_line { 'dnf_clean_old_pkgs':
    path  => '/etc/dnf/dnf.conf',
    line  => 'clean_requirements_on_remove=True',
    match => '^clean_requirements_on_remove',
  }

file_line { 'inactive_35_days_useradd':
    path  => '/etc/default/useradd',
    line  => 'INACTIVE=35',
    match => '^INACTIVE',
  }

  file_line { 'disable_core_dumps':
    path  => '/etc/systemd/coredump.conf',
    line  => 'Storage=none',
    match => 'Storage=none',
  }

  file_line { 'disable_dump_backtrace':
    path  => '/etc/systemd/coredump.conf',
    line  => 'ProcessSizeMax=0',
    match => 'ProcessSizeMax=',
  }

  file_line { 'systemd_ctrl-alt-del_burst':
    path  => '/etc/systemd/system.conf',
    line  => 'CtrlAltDelBurstAction=none',
    match => '^FirewallBackend=',
  }


  file { '/etc/pam.d/postlogin':
        ensure => file,
        mode   => '0644',
        source => 'puppet:///modules/rhel8_stig/postlogin',
  }

  file { '/etc/issue.net':
        ensure => file,
        mode   => '0644',
        source => 'puppet:///modules/rhel8_stig/issue.net',
  }

  file { '/etc/chrony.conf':
        ensure => file,
        mode   => '0644',
        source => 'puppet:///modules/rhel8_stig/chrony.conf',
  }

  file { '/etc/crypto-policies/back-ends/gnutls.config':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/gnutls.config',
  }

  file { '/etc/pam.d/system-auth':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/system-auth',
  }

  file { '/etc/pam.d/password-auth':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/password-auth',
  }

  file { '/etc/sssd/conf.d/99-stig-sssd.conf':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/99-stig-sssd.conf',
  }

  package {'aide':
    ensure => present,
  }

  file { '/etc/aide.conf':
        ensure  => file,
        mode    => '0600',
        source  => 'puppet:///modules/rhel8_stig/aide.conf',
        require => Package['aide'],
  }

  file { '/etc/audit/rules.d/stig.rules':
      ensure => file,
      mode   => '0640',
      source => 'puppet:///modules/rhel8_stig/stig_audit.rules',
  }

  file { lookup('audit_files_755', Array):
    ensure => file,
    mode   => '0755',
    owner  => 'root',
    group  => 'root',
  }

  file { lookup('audit_files_750', Array):
      ensure => file,
      mode   => '0755',
      owner  => 'root',
      group  => 'root',
    }

  file { '/etc/modprobe.d/stig_blacklist.conf':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/stig_blacklist.conf',
  }

  mount { '/var/tmp':
    options => 'defaults,noexec,nosuid,nodev,x-systemd.device-timeout=0',
  }

  mount { '/var/log/audit':
    options => 'defaults,noexec,nosuid,nodev,x-systemd.device-timeout=0',
  }

  mount { '/var/log':
      options => 'defaults,noexec,nosuid,nodev,x-systemd.device-timeout=0',
  }

  mount { '/tmp':
    options => 'defaults,noexec,nosuid,nodev,x-systemd.device-timeout=0',
  }

  mount { '/home':
    options => 'defaults,noexec,nosuid,nodev,x-systemd.device-timeout=0',
  }

  mount { '/boot':
    options => 'defaults,nosuid',
  }

  mount { '/dev/shm':
    ensure  => present,
    device  => 'tmpfs',
    fstype  => 'tmpfs',
    options => 'defaults,noexec,nosuid,nodev,x-systemd.device-timeout=0',
  }

  file_line { 'grub_user':
    path  => '/boot/grub2/grub.cfg',
    line  => 'set superusers="grubadmin"',
    match => 'set superusers=',
  }

  exec { 'verify_grub_user':
    command  => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
    register => File_line['grub_user'],
  }
}
