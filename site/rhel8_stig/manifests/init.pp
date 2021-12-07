class rhel8_stig {
#   # run exec only if command in onlyif returns 0.
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

  package { 'vim':
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

  package { 'opensc':
      ensure => present,
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

  package { 'openssl-pkcs11':
      ensure => present,
  }

package { 'policycoreutils':
      ensure => present,
  }

  package { 'audit':
    ensure => present,
  }

  service { 'auditd':
    ensure => running,
    enable => true,
  }

#   file { '/etc/pam_pkcs11':
#       ensure  => directory,
#       mode    => '0755',
#       require => 'Package[openssl-pkcs11'],
#   }

#   file { '/etc/pam_pkcs11/pam_pkcs11.conf':
#       ensure => file,
#       mode   => '0644',
#       source => 'puppet:///modules/rhel8_stig/login.defs',
#       require => 'Package[openssl-pkcs11'],

#   }

  file { '/etc/ssh/sshd_config':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/sshd_config',
  }

  file { '/etc/pam.d/password-auth':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/password-auth',
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
  }


  file { '/etc/security/limits.conf':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/limits.conf',
  }

  file { '/etc/security/faillock.conf':
      ensure => file,
      mode   => '0644',
      source => 'puppet:///modules/rhel8_stig/faillock.conf',
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

#   file_line { 'secure_rescue_mode':
#     path  => '/usr/lib/systemd/system/rescue.service',
#     line  => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue',
#     match => '^ExecStart=',
#   }

#   file_line { 'selinux_mode':
#     path  => '/etc/selinux/config',
#     line  => 'SELINUX=enforcing',
#     match => '^SELINUX=',
#   }

#   file_line { 'selinux_type':
#     path  => '/etc/selinux/config',
#     line  => 'SELINUXTYPE=targeted',
#     match => '^SELINUXTYPE=',
#   }

#   file_line { 'tls_min_level':
#     path  => '//etc/crypto-policies/back-ends/opensslcnf.config',
#     line  => 'TLS.MinProtocol = TLSv1.2',
#     match => '^TLS.MinProtocol',
#   }

#   file_line { 'profile_timeout':
#     path => '/etc/bash.bashrc',
#     line => 'TMOUT=600',
#   }

#   file_line { 'sssd_ocsp_dgst':
#     path  => '/etc/sssd/sssd.conf',
#     line  => 'certificate_verification = ocsp_dgst=sha1',
#     match => '^certificate_verification',
#   }

#   file_line { 'ssh_strong_rng':
#     path  => '/etc/sysconfig/sshd',
#     line  => 'SSH_USE_STRONG_RNG=32',
#     match => '^SSH_USE_STRONG_RNG=',
#   }

# file_line { 'dnf_local_pkg_gpgcheck':
#     path  => '/etc/dnf/dnf.conf',
#     line  => 'localpkg_gpgcheck=True',
#     match => '^localpkg_gpgcheck=',
#   }

# file_line { 'dnf_clean_old_pkgs':
#     path  => '/etc/dnf/dnf.conf',
#     line  => 'clean_requirements_on_remove=True',
#     match => '^clean_requirements_on_remove',
#   }

# file_line { 'inactive_35_days_useradd':
#     path  => '/etc/default/useradd',
#     line  => 'INACTIVE=35',
#     match => '^INACTIVE',
#   }

#   file_line { 'disable_core_dumps':
#     path  => '/etc/systemd/coredump.conf',
#     line  => 'Storage=none',
#     match => 'Storage=none',
#   }

#   file_line { 'disable_dump_backtrace':
#     path  => '/etc/systemd/coredump.conf',
#     line  => 'ProcessSizeMax=0',
#     match => 'ProcessSizeMax=',
#   }

#   file { '/etc/pam.d/postlogin':
#         ensure => file,
#         mode   => '0644',
#         source => 'puppet:///modules/rhel8_stig/postlogin',
#   }

  file { '/etc/issue.net':
        ensure => file,
        mode   => '0644',
        source => 'puppet:///modules/rhel8_stig/issue.net',
  }

#   package {'libpam-pwquality':
#     ensure => present,
#     before => File['/etc/security/pwquality.conf'],
#   }

#   file { '/etc/crypto-policies/back-ends/gnutls.config':
#       ensure => file,
#       mode   => '0644',
#       source => 'puppet:///modules/rhel8_stig/gnutls.config',
#   }

#   package {'opensc-pkcs11':
#     ensure => present,
#   }

#   file { '/etc/pam.d/common-password':
#       ensure => file,
#       mode   => '0644',
#       source => 'puppet:///modules/rhel8_stig/common-password',
#   }

#   file { '/etc/security/faillock.conf':
#       ensure => file,
#       mode   => '0644',
#       source => 'puppet:///modules/rhel8_stig/faillock.conf',
#   }

  package {'aide':
    ensure => present,
  }

#   file { '/etc/audit/rules.d/stig.rules':
#       ensure => file,
#       mode   => '0644',
#       source => 'puppet:///modules/rhel8_stig/stig_audit.rules',
#   }

  file { lookup('audit_files_755', Array):
    ensure => file,
    mode   => '0755',
    owner  => 'root',
    group  => 'root',
  }
}
