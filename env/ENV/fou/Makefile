obj-m := fou.o

all:
	make -Werror -Wextra -Wall -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean

