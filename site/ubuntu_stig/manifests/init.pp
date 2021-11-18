class ubuntu_stig {

  user {'admin': 
  ensure => present 
  }

  package { 'vlock': 
      ensure => present,
  }

  package { 'ssh':
    ensure => present,
  }

  service { 'ssh':
    ensure => running,
    enable => true,
  }

  package { 'libpam-pkcs11':
      ensure => present,
  }

  file { '/etc/pam_pkcs11':
      ensure => directory,
      mode => '755',
  }

  file { '/etc/pam_pkcs11/pam_pkcs11.conf':
      ensure  => file,
      mode    => '755',
      source => 'puppet:///modules/ubuntu_stig/login.defs',
  }

  file { '/etc/ssh/sshd_config':
      ensure => file,
      mode => '755',
      source => 'puppet:///modules/ubuntu_stig/sshd_config',
  }

  file { '/etc/login.defs':
      ensure => file,
      mode => '755',
      source => 'puppet:///modules/ubuntu_stig/login.defs',
  }

  grub_user { 'root':
    password    => 'Temp1234!',
    superuser   => true,
    before      => Exec['update-grub'],
  }

  exec { 'update-grub':
    command => '/usr/sbin/update-grub',
    onlyif => '/usr/bin/grep -i password /boot/grub/grub.cfg'
  }

  file_line { 'profile_timeout':
    path => '/etc/bash.bashrc',
    line => 'TMOUT=600',
  }

  file_line { 'pam_common_auth_pkcs11':
      path => '/etc/pam.d/common-auth',
      line => 'auth [success=2 default=ignore] pam_pkcs11.so',
  }

  file { '/etc/issue.net':
        ensure => file,
        mode => '755',
        source => 'puppet:///modules/ubuntu_stig/issue.net',
  }

  package {'libpam-pwquality':
    ensure => present,
    before => File['/etc/security/pwquality.conf'],
  }

  file { '/etc/security/pwquality.conf':
      ensure  => file,
      mode    => '755',
      source => 'puppet:///modules/ubuntu_stig/pwquality.conf',
  }

  package {'opensc-pkcs11':
    ensure => present,
  }

  file { '/etc/pam.d/common-password':
      ensure  => file,
      mode    => '755',
      source => 'puppet:///modules/ubuntu_stig/common-password',
  }

  file { '/etc/security/faillock.conf':
      ensure  => file,
      mode    => '755',
      source => 'puppet:///modules/ubuntu_stig/faillock.conf',
  }

  package {'aide':
    ensure => present,
  }

}
