# KTCP 
 KTCP is a kernel module implementing a TCP-Split Proxy.
 zero-copy forwarding in experimental stages.

KTCP captures and redirets marked pakets. Please see *env* dir for examples. 
## Building
make

## Testing:
The **env** directory contains sripts that can be used to bring-up a test environment.

1. setup\_env.pl: connects several machines with gue tunnels and configs ktcp on the intermediate machines.

***All scripts assume a key is used to connect to other machines. Make sure to change MASTER_KEY accordingly***
	$cat env/configs/config_mc.txt
		src  10.128.0.12
		sink 10.128.0.13
		link 10.128.0.14
		link 10.128.0.15

	1. setup\_env.pl -r -f configs/config\_mc.txt

	will:
		- reboot the listed machines (-r flag)
		- copy the scripts and configurations
		- setup ktcp on the __link__ machines
		- will create a *params.txt* file to be used by open\_env.sh/open_serial.sh
	1. run iperf/netper/etc... between src and sink

1. open\_env.sh: creates a tmux window showing the 4 machines.
	This script assumes you are using a key for ssh auth.
1. open\serial.sh: creates a tmux window showing the serial connection for two **GCP** vms.
    (Please update the ssh\_console.sh script with your VM info: key/user/region/etc...)

## Zero Copy
	The split.c file includea a version of the zero-copy half\_duplex function.
	This version depends on a modified kernel with a modified send_msg function. 
	The code can be trivialy addopted to use send\_page instead.
