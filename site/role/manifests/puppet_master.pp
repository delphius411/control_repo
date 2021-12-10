# this class creates a wrapper to the custom 
# r10k setup to allow for github webhooks.
class role::puppet_master {
  include profile::r10k
}
