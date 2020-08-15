#!/bin/bash

sudo apt-get install -y tmux

[ "$CONFIG" ] || CONFIG=params.txt

[ ! -f "$CONFIG" ] && echo $CONFIG not found && exit -1;

source $CONFIG

[ "$KEY" ] || KEY='~/MASTER_KEY'

SESS="ENV_$BASHPID"
tmux new-session -d -s$SESS

tmux split-window -h
tmux select-pane -t 0
tmux split-window -v
tmux select-pane -t 2
tmux split-window -v

#we now have 4 open panes
# 0 2
# 1 3
# use $prfx q (prfx=ctl b)
for i in `seq 0 3`;
do
	tmux select-pane -t $i
	NAME="PANE_${i}"
	eval PANE=\$$NAME;
	#tmux send-keys "echo \"$i) $NAME -> $PANE\"" C-m
	tmux send-keys "ssh -i $KEY $PANE" C-m
	tmux send-keys "cd ~/ENV/; clear; ls -l; ip link show" C-m
done

tmux attach-session -t $SESS

#use $prfx & to close session
