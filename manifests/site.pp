node default {
  file {'/root/README':
    ensure => file,
    }
}
node 'client1.lab.net' {
  
}

node 'netsvcs.lab.net' {
  
}
