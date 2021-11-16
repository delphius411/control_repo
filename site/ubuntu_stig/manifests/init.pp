class ubuntu_stig {

  user {'admin': 
  ensure => present 
  }

  package { 'vlock': 
      ensure => present,
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



}
