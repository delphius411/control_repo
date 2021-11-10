node default {
  file {'/root/README':
    ensure => file,
    }
}
node 'client1.lab.net' {
  
}

node 'netsvcs.lab.net' {
  file {'/root/README':
    ensure => file,
    content => 'This is a readme created by puppet.',
    }
}
