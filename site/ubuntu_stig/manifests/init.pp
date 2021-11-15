class ubuntu_stig {

  user {'admin': 
  ensure => present 
  }

  package { 'vlock': 
      ensure => installed,
  }

  package { 'libpam_pkcs11':
      ensure => installed,
  }

  file { '/etc/pam_pkcs11':
      ensure => directory,
      mode => 755,
  }

  file { '/etc/pam_pkcs11/pam_pkcs11.conf':
      ensure  => file,
      mode    => 755,
      source => 'puppet:///modules/ubuntu_stig/login.defs',
  }

  file { '/etc/login.defs':
      ensure => file,
      mode => 755,
      source => 'puppet:///modules/ubuntu_stig/login.defs',
  }
}
