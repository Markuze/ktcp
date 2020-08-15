#include <linux/init.h>      // included for __init and __exit macros
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include "cbn_common.h"
#include "tcp_split.h"
#include "proc.h"
#include "debug.h"

extern uint32_t ip_transparent;

static int cbn_proc_show(struct seq_file *m, void *v)
{
	int idx;
	char *buffer = proc_read_string(&idx);

	ERR_LINE();
	if (!buffer)
		return -EAGAIN;
	pr_err("buffer %p [%d]\n", buffer, idx);
	pr_err("%s\n", buffer);
	if (idx)
		seq_puts(m, buffer);
	kfree(buffer);
	seq_printf(m, "buffer len = %d/4096", idx);
	/* show tennat - port pairs */
	return idx;
}

static int cbn_proc_open(struct inode *inode, struct  file *file)
{
	return single_open(file, cbn_proc_show, NULL);
}

#define PROC_CSV_NUM 2
static ssize_t cbn_add_server(struct file *file, const char __user *buf,
				    size_t size, loff_t *_pos)
{
	char *kbuf;
	int   values[PROC_CSV_NUM + 1] = {0};

	/* start by dragging the command into memory */
	if (size <= 1 || size >= PAGE_SIZE)
		return -EINVAL;

	kbuf = memdup_user_nul(buf, size);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	get_options(kbuf, ARRAY_SIZE(values), values);

	/* start new server */
	kfree(kbuf);
	if (values[0] == PROC_CSV_NUM) {
		add_server_cb(values[1], values[2]);
	} else {
		pr_err("Failed to start new server %d\n" ,values[2]);
		size = -EINVAL;
	}
	ERR_LINE();
	return size;
}

static ssize_t cbn_del_server(struct file *file, const char __user *buf,
				    size_t size, loff_t *_pos)
{
	char *kbuf;
	int   values[PROC_CSV_NUM + 1] = {0};

	/* start by dragging the command into memory */
	if (size <= 1 || size >= PAGE_SIZE)
		return -EINVAL;

	kbuf = memdup_user_nul(buf, size);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	get_options(kbuf, ARRAY_SIZE(values), values);

	/* start new server */
	kfree(kbuf);
	if (values[0] == 1) {
		del_server_cb(values[1]);
	} else {
		pr_err("Invalid num of params for del server %d\n" ,values[0]);
		size = -EINVAL;
	}
	ERR_LINE();
	return size;
}
#define IP_LEN 4
static ssize_t preconn_proc_command(struct file *file, const char __user *buf,
				    size_t size, loff_t *_pos)
{
	char *kbuf;
	int   values[IP_LEN + 1] = {0};

	/* start by dragging the command into memory */
	if (size <= 1 || size >= PAGE_SIZE)
		return -EINVAL;

	kbuf = memdup_user_nul(buf, size);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	get_options(kbuf, ARRAY_SIZE(values), values);

	/* start new server */
	kfree(kbuf);
	if (values[0] == IP_LEN) {
		preconn_write_cb(&values[1]);
	} else {
		pr_err("ERROR: Failed to start new pre connection %d (ip has 4 digits)\n" ,values[0]);
		size = -EINVAL;
	}
	ERR_LINE();
	return size;
}
static int cbn_version_show(struct seq_file *m, void *v)
{
	pr_info("%d\n", ip_transparent);
	seq_printf(m, "%s\n", KTCP_VERSION);
	ERR_LINE();
	return 0;
}

static int cbn_version_open(struct inode *inode, struct  file *file)
{
	return single_open(file, cbn_version_show, NULL);
}

static int cbn_transparent_show(struct seq_file *m, void *v)
{
	pr_info("%d\n", ip_transparent);
	seq_printf(m, "%u\n", ip_transparent);
	ERR_LINE();
	return 0;
}

static int cbn_transparent_open(struct inode *inode, struct  file *file)
{
	return single_open(file, cbn_transparent_show, NULL);
}

static ssize_t cbn_transparent_command(struct file *file, const char __user *buf,
					size_t size, loff_t *_pos)
{
	char *kbuf;
	int   values[2] = {0};

	/* start by dragging the command into memory */
	if (size <= 1 || size >= PAGE_SIZE)
		return -EINVAL;

	kbuf = memdup_user_nul(buf, size);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	get_options(kbuf, ARRAY_SIZE(values), values);

	/* start new server */
	kfree(kbuf);

	if (values[0] == 1 && (values[1] == 0 ||values[1] == 1))
		ip_transparent = values[1];
	else
		size = -EINVAL;

	ERR_LINE();
	return size;
}

static ssize_t connections_read(struct file *file, char __user *buf,
		                             size_t len, loff_t *ppos)
{
	int rc = 0;

	if (!buf)
		return -EINVAL;

	if (file->f_pos)
		goto out;

	rc =  dump_connections(buf, len);
out:
	*ppos ^= 1;

	return rc;
}

static const struct file_operations connections_fops = {
	.owner		= THIS_MODULE,
	.open		= cbn_proc_open,
	.read 		= connections_read,
	//write		= noop_write,
	.llseek 	= seq_lseek,
	.release 	= single_release,
};

static const struct file_operations preconn_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= cbn_proc_open,
	.read 		= seq_read,
	.write		= preconn_proc_command,
	.llseek 	= seq_lseek,
	.release 	= single_release,
};

static const struct file_operations cbn_add_fops = {
	.owner		= THIS_MODULE,
	.open		= cbn_proc_open,
	.read 		= seq_read,
	.write		= cbn_add_server,
	.llseek 	= seq_lseek,
	.release 	= single_release,
};

static const struct file_operations cbn_del_fops = {
	.owner		= THIS_MODULE,
	.open		= cbn_proc_open,
	.read 		= seq_read,
	.write		= cbn_del_server,
	.llseek 	= seq_lseek,
	.release 	= single_release,
};

static const struct file_operations cbn_transparent_fops = {
	.owner		= THIS_MODULE,
	.open		= cbn_transparent_open,
	.read 		= seq_read,
	.write		= cbn_transparent_command,
	.llseek 	= seq_lseek,
	.release 	= single_release,
};

static const struct file_operations cbn_version_fops = {
	.owner		= THIS_MODULE,
	.open		= cbn_version_open,
	.read 		= seq_read,
	.release 	= single_release,
};

static struct proc_dir_entry *cbn_dir;

int __init cbn_proc_init(void)
{
	cbn_dir = proc_mkdir_mode("cbn", 00555, NULL);
	proc_create("connections", 00666, cbn_dir, &connections_fops);
	proc_create("cbn_proc", 00666, cbn_dir, &cbn_add_fops);
	proc_create("cbn_del", 00666, cbn_dir, &cbn_del_fops);
	proc_create("conn_pool", 00666, cbn_dir, &preconn_proc_fops);
	proc_create("cbn_transparent", 00666, cbn_dir, &cbn_transparent_fops);
	proc_create("version", 00444, cbn_dir, &cbn_version_fops);
	return 0;
}

void __exit cbn_proc_clean(void)
{
	remove_proc_subtree("cbn", NULL);
}
