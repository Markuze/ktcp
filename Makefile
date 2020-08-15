obj-m := cbn_split.o
cbn_split-y := split.o thread_pool.o proc.o conn_pool.o magazine.o qp.o debug.o zero-copy.o

all:
	make -Werror -Wextra -Wall -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean

