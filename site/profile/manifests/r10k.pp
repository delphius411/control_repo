# This class is used to setup webhooks to a Github repo
class profile::r10k {
  class {'r10k':
    remote => 'https://github.com/delphius411/control_repo.git',
  }
  class {'r10k::webhook::config':
    use_mcollective => false,
    enable_ssl      => false,
  }
  class { 'r10k::webhook':
    user  => root,
    group => root,
  }

}
