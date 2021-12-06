class rhel8_stig {

  
  # run exec only if command in onlyif returns 0.
  exec { 'verify_fips_mode':
    command => 'fips-mode-setup --enable',
    onlyif  => 'grep 0 /proc/sys/crypto/fips_enabled',
  }

  package { 'vlock': 
      ensure => present,
  }

  package { 'vim': 
      ensure => present,
  }

  package { 'rng-tools': 
      ensure => present,
  }

  service { 'rngd':
    ensure => running,
    enable => true,
    require => Package['rng-tools'],
  }

  service { 'systemd-coredump.socket':
    ensure => stopped,
    enable => mask,
  }

  package { 'opensc': 
      ensure => present,
  }

  package { 'ssh':
    ensure => present,
  }

  service { 'ssh':
    ensure => running,
    enable => true,
    require => Package['ssh'],
  }

  package { 'rsyslog':
    ensure => present,
  }

  service { 'rsyslog':
    ensure => running,
    enable => true,
    require => Package['rsyslog'],
  }

file { '/etc/rsyslog.conf':
      ensure  => file,
      mode    => '644',
      source => 'puppet:///modules/rhel8_stig/rsyslog.conf',
      require => Package['rsyslog'],
  }

  package { 'openssl-pkcs11':
      ensure => present,
  }

package { 'policycoreutils':
      ensure => present,
  }

  package { 'auditd': 
    ensure => present,
  }

  service { 'auditd':
    ensure => running,
    enable => true,
  }

  file { '/etc/pam_pkcs11':
      ensure => directory,
      mode => '755',
  }

  file { '/etc/pam_pkcs11/pam_pkcs11.conf':
      ensure  => file,
      mode    => '644',
      source => 'puppet:///modules/rhel8_stig/login.defs',
  }

  file { '/etc/ssh/sshd_config':
      ensure => file,
      mode => '644',
      source => 'puppet:///modules/rhel8_stig/sshd_config',
  }

  file { '/etc/pam.d/password-auth':
      ensure => file,
      mode => '644',
      source => 'puppet:///modules/rhel8_stig/password-auth',
  }

   file { '/etc/issue':
      ensure => file,
      mode => '644',
      source => 'puppet:///modules/rhel8_stig/issue',
  }

  file { '/etc/login.defs':
      ensure => file,
      mode => '644',
      source => 'puppet:///modules/rhel8_stig/login.defs',
  }

  file { '/usr/share/crypto-policies/DEFAULT/opensshserver.txt':
      ensure => file,
      mode => '644',
      source => 'puppet:///modules/rhel8_stig/crypto_opensshserver.config',
  }

  file { '/var/log/messages': 
    ensure => file,
    mode => '640',
    owner => 'root',
    group => 'root',
  }

file { '/var/log':
  ensure => directory,
  mode => '755',
  owner => 'root',
  group => 'root',
}

 file { '/etc/security/limits.conf':
      ensure => file,
      mode => '644',
      source => 'puppet:///modules/rhel8_stig/limits.conf',
  }


  #grub_user { 'root':
  #  password    => 'Temp1234!',
  #  superuser   => true,
  #  before      => Exec['update-grub'],
  #}

  #exec { 'update-grub':
  #  command => '/usr/sbin/update-grub',
  #  onlyif => '/usr/bin/grep -i password /boot/grub/grub.cfg'
  #}

  file_line { 'secure_rescue_mode':
    path => '/usr/lib/systemd/system/rescue.service',
    line => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue',
    match => '^ExecStart=',
  }

file_line { 'selinux_mode':
    path => '/etc/selinux/config',
    line => 'SELINUX=enforcing',
    match => '^SELINUX=',
  }

  file_line { 'selinux_type':
    path => '/etc/selinux/config',
    line => 'SELINUXTYPE=targeted',
    match => '^SELINUXTYPE=',
  }

  file_line { 'tls_min_level':
    path => '//etc/crypto-policies/back-ends/opensslcnf.config',
    line => 'TLS.MinProtocol = TLSv1.2',
    match => '^TLS.MinProtocol',
  }

  file_line { 'profile_timeout':
    path => '/etc/bash.bashrc',
    line => 'TMOUT=600',
  }

file_line { 'sssd_ocsp_dgst':
    path => '/etc/sssd/sssd.conf',
    line => 'certificate_verification = ocsp_dgst=sha1',
    match => '^certificate_verification',
  }  

file_line { 'ssh_strong_rng':
    path => '/etc/sysconfig/sshd',
    line => 'SSH_USE_STRONG_RNG=32',
    match => '^SSH_USE_STRONG_RNG=',
  }

file_line { 'dnf_local_pkg_gpgcheck':
    path => '/etc/dnf/dnf.conf',
    line => 'localpkg_gpgcheck=True',
    match => '^localpkg_gpgcheck=',
  }

file_line { 'dnf_clean_old_pkgs':
    path => '/etc/dnf/dnf.conf',
    line => 'clean_requirements_on_remove=True',
    match => '^clean_requirements_on_remove',
  }

  file_line { 'disable_core_dumps':
    path => '/etc/systemd/coredump.conf',
    line => 'Storage=none',
  }


  file { '/etc/issue.net':
        ensure => file,
        mode => '644',
        source => 'puppet:///modules/rhel8_stig/issue.net',
  }

  package {'libpam-pwquality':
    ensure => present,
    before => File['/etc/security/pwquality.conf'],
  }

  file { '/etc/crypto-policies/back-ends/gnutls.config':
      ensure  => file,
      mode    => '644',
      source => 'puppet:///modules/rhel8_stig/gnutls.config',
  }

  package {'opensc-pkcs11':
    ensure => present,
  }

  file { '/etc/pam.d/common-password':
      ensure  => file,
      mode    => '644',
      source => 'puppet:///modules/rhel8_stig/common-password',
  }

  file { '/etc/security/faillock.conf':
      ensure  => file,
      mode    => '644',
      source => 'puppet:///modules/rhel8_stig/faillock.conf',
  }

  package {'aide':
    ensure => present,
  }

  file { '/etc/audit/rules.d/stig.rules':
      ensure => file,
      mode => '644',
      source => 'puppet:///modules/rhel8_stig/stig_audit.rules',
  }

}
