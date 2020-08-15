#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/tcp.h>
#include <net/tcp.h>

#include "tcp_split.h"

struct kvec_desc {
	struct kvec *pages_array;
	unsigned int nr_pages;
	read_descriptor_t desc_t;
};

static inline void skb_frag_get(const skb_frag_t *frag)
{
	get_page(compound_head(skb_frag_page(frag)));
}

int skb_zerocopy_rx(read_descriptor_t *desc_t, struct sk_buff *skb, u32 offset, size_t len)
{
	int copied = 0, skipped = 0;
	const skb_frag_t *frags;
	struct kvec_desc *desc = container_of(desc_t, struct kvec_desc, desc_t);

	desc_t->count = desc->nr_pages;
//	trace_printk("Collecting : %d  off %u len %lu\n", desc->nr_pages, offset, len);

	if (unlikely(!desc->nr_pages)) {
//		trace_printk("nr_pages = 0\n");
		return -ENOMEM;
	}

	if (skb_headlen(skb) > offset) {
		if (!(skb->head_frag)) {
			trace_printk("head_frag error...\n");
			return -EINVAL;
		}

		desc->pages_array->iov_base = skb->data + offset;
		desc->pages_array->iov_len = skb_headlen(skb) - offset;
		copied = desc->pages_array->iov_len;
		len -= copied;

		get_page(virt_to_head_page(skb->head));
#if 0
		trace_printk("Head: %p<%d> [%lu/%lu] [%d,%d] (?%d)\n",
				virt_to_head_page(desc->pages_array->iov_base),
				page_count(virt_to_head_page(desc->pages_array->iov_base)),
				desc->pages_array->iov_len, len, copied, desc->nr_pages, offset);
#endif
		offset = 0;
		desc->pages_array++;
		desc->nr_pages--;
		desc_t->count = desc->nr_pages;
	} else {
		offset -= skb_headlen(skb);
	}

	if (offset > skb->data_len) {
		trace_printk("WEIRD?!: %p len %d data len %d of %d copied %d\n", skb, skb->len, skb->data_len, offset, copied);
		return copied;
	}

	len = skb->data_len - offset;
	if (unlikely(!len)) {
//		trace_printk("%p len %d data len %d of %d copied %d\n", skb, skb->len, skb->data_len, offset, copied);
		return copied;
	}

	frags = skb_shinfo(skb)->frags;
	while (offset) {
		if (frags->size > offset)
			break;
		offset -= frags->size;
		skipped++;
		frags++;
	}

//	trace_printk("Collecting frags: %d [%d] of %u len %lu\n", skb_shinfo(skb)->nr_frags, skipped, offset, len);

	while (desc->nr_pages) {
		//if (unlikely(!(skb_shinfo(skb)->nr_frags -skipped))) {
		if (unlikely(skb_shinfo(skb)->nr_frags <= skipped)) {
			break;
		}
		desc->pages_array->iov_base = skb_frag_address(frags) + offset;
		desc->pages_array->iov_len = skb_frag_size(frags) - offset;


		len -= skb_frag_size(frags);
		copied += skb_frag_size(frags);
#if 0
		trace_printk("Frag: %p [%d]<%d> [%lu=%u/%lu] [%d,%d]\n",
				virt_to_head_page(desc->pages_array->iov_base), frags->page_offset + offset,
				page_count(virt_to_head_page(desc->pages_array->iov_base)),
				desc->pages_array->iov_len, skb_frag_size(frags), len, copied, desc->nr_pages);
#endif
		skb_frag_get(frags);//TODO: BUG - Doesnt use compound head!!! - GRO use case breaks
		offset = 0;
		desc->pages_array++;
		desc->nr_pages--;
		skipped++;
		frags++;

		if (len <= 0)
			break;
	}

	desc_t->count = desc->nr_pages;
	BUG_ON(!copied);
	return copied;
}

int tcp_read_sock_zcopy_blocking(struct socket *sock,
					struct kvec *pages_array,
					unsigned int nr_pages)
{
	struct sock *sk = sock->sk;
//	struct sk_buff *last = NULL;
	long timeo = 1 * HZ;//MAX_SCHEDULE_TIMEOUT;
	int rc;

	if (skb_queue_empty(&sk->sk_receive_queue))
		goto wait;

retry:
	if ((rc = tcp_read_sock_zcopy(sock, pages_array, nr_pages)) < 0) {
		trace_printk("Error %d\n", rc);
		goto out;
	}
	if (!rc) {
wait:
		//trace_printk("Waiting... \n");
		lock_sock(sk);
		timeo = 1/HZ;
		rc = sk_wait_data(sock->sk, &timeo, NULL);
		//last = skb_peek_tail(&sk->sk_receive_queue);
		release_sock(sk);
		goto retry;
	}
out:
	return rc;
}
EXPORT_SYMBOL(tcp_read_sock_zcopy_blocking);

int tcp_read_sock_zcopy(struct socket *sock, struct kvec *pages_array, unsigned int nr_pages)
{
	int rc = 0;
	struct kvec_desc desc = {.pages_array = pages_array, .nr_pages = nr_pages};

	lock_sock(sock->sk);
	rc =  tcp_read_sock(sock->sk, &desc.desc_t , skb_zerocopy_rx);
	release_sock(sock->sk);
	return rc;

}
EXPORT_SYMBOL(tcp_read_sock_zcopy);
