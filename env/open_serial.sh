#!/bin/bash

if [ ! -f ./params.txt ]; then
	echo "./params.txt doesnt exist";
	exit -1;
fi


source ./params.txt


vm1=`ssh -i ~/MASTER_KEY  $PANE_0 hostname`
vm2=`ssh -i ~/MASTER_KEY  $PANE_2 hostname`

echo "$vm1"
echo "$vm2"

SESS="SERIAL_$BASHPID"
tmux new-session -d -s$SESS

tmux split-window -h

#we now have 2 open panes
# 0 1
tmux select-pane -t 0
tmux send-keys "vm=$vm1 ./ssh_console.sh " C-m

tmux select-pane -t 1
tmux send-keys "vm=$vm2 ./ssh_console.sh " C-m

tmux attach-session -t $SESS

#use $prfx & to close session
