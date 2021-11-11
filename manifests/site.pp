node default {

}
node 'client1.lab.net' {
  include role::master_server
}

node 'netsvcs.lab.net' {
  
  file {'/root/README':
    ensure  => file,
    content => 'This is a readme created by puppet.',
    owner   => 'root',
    }
}
