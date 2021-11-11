node default {

}
node 'client1.lab.net' {
  include role::master_server
}

node 'netsvcs.lab.net' {
  
  file {'/root/README':
    ensure  => file,
    content => $fqdn,
    owner   => 'root',
    }
}
