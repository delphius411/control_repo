node default {
}

node 'client1.lab.net' {
  include role::master_server
}

node 'client2.lab.net' {
  include role::rhel8_secure_server
}

node 'netsvcs.lab.net' {

  file {'/root/README':
    ensure  => file,
    content => "Welcome to ${fqdn}",
    owner   => 'root',
    }
}

node 'ubuntustig.lab.net' {
  include role::ubuntu_secure_server
}
