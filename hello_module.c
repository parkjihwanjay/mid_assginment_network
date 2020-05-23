#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>

/* Like Group Number */
#define NETLINK_USER 31

/* Message Type */
#define MSG_REGISTER 1
#define MSG_REGISTER_RESPONSE 2
#define MSG_DEREGISTER 3
#define MSG_DEREGISTER_RESPONSE 4
#define MSG_GET 5
#define MSG_GET_RESPONSE 6

/* Message Code for Response Message */
#define MSG_SUCCESS 0
#define MSG_FAILED 1

#define SET_MSG_CHAR(name, x) (*name = x); \
					(name += 1);
#define SET_MSG_SHORT(name, x) (*(unsigned short *)name = htons(x)); \
					(name += sizeof(unsigned short));
#define SET_MSG_INTEGER(name, x) (*(unsigned int *)name = htonl(x)); \
					(name += sizeof(unsigned int));
#define SET_MSG_STRING(name, x) { strcpy(name, x); name += strlen(x)+1; }

#define LIST_ITEM_INITIALIZE(list_item, item_name, address) { strcpy(list_item->name, item_name); list_item->ipv4 = address; list_item->next = NULL; }

/* Initialization macro for hostname---ipv4_address entry data */


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nam");
MODULE_DESCRIPTION("Mid-term Assignment NetLink Module");

struct list_node {
	char name[40];
	unsigned int ipv4;
	struct list_node * next;
};

struct list_node * registeredLinkedList = NULL; // head of linked list

struct sock * nl_sk = NULL; // netlink socket pointer


static unsigned short set_response_message_header(unsigned char type, unsigned char code, unsigned short msg_len, char * msg) { // function to make response message header 
	SET_MSG_CHAR(msg, type)
	SET_MSG_CHAR(msg, code)
	SET_MSG_SHORT(msg, msg_len)
	return msg_len;
}

// Add received (hostname --- ipv4_address) data to linked list
static unsigned short add_item_to_reg_list(char * data, char * msg) {
	// data format is AAAA NNNNN..\0 => get ipv4_addr then add 4 to data => will point string
	unsigned int ipv4_addr = *((unsigned int *)data);
	char * name = data + 4;

	struct list_node * ptr = registeredLinkedList; // initialize for traversing list
	struct list_node * new_node = NULL;

	printk(KERN_INFO "Entering %s\n", __FUNCTION__);
	printk(KERN_INFO "Try to register %d, %s\n", ipv4_addr, name);

	if(registeredLinkedList == NULL) { // => No data in linked list => immediately add
		new_node = (struct list_node *)kmalloc(sizeof(struct list_node), GFP_KERNEL);
		LIST_ITEM_INITIALIZE(new_node, name, ipv4_addr)
		registeredLinkedList = new_node;
		printk(KERN_INFO "Registration Success\n");
		return set_response_message_header(MSG_REGISTER_RESPONSE, MSG_SUCCESS, 4, msg);
	}

	for(; ptr != NULL;) { // => Traverse linked list
		if(strcmp(ptr->name, name) == 0) { // Is there a entry (name, ipv4_addr)? If exists, print error
			printk(KERN_INFO "Registration Failed - Hostname already exists\n");
			return set_response_message_header(MSG_REGISTER_RESPONSE, MSG_FAILED, 4, msg);
		}
		if(ptr->next == NULL) { // next is NULL => Entry for (name, ipv4_addr) doesn't exist => Add
			new_node = (struct list_node *)kmalloc(sizeof(struct list_node), GFP_KERNEL);
			LIST_ITEM_INITIALIZE(new_node, name, ipv4_addr)
			ptr->next = new_node;
			break;
		} else
			ptr = ptr->next;
	}
	
	printk(KERN_INFO "Registration Success\n");

	return set_response_message_header(MSG_REGISTER_RESPONSE, MSG_SUCCESS, 4, msg);
}

static unsigned short del_item_to_reg_list(char * data, char * msg) { // Delete entry from list


	unsigned int ipv4_addr = *((unsigned int *)data); // Get addr, name from data using message format
	char * name = data + 4;

	struct list_node * ptr = registeredLinkedList; // initialize for traversing
	struct list_node * previous_ptr = NULL;

	printk(KERN_INFO "Entering %s\n", __FUNCTION__);
	printk(KERN_INFO "Try to de-register %s\n", data);

	for(; ptr != NULL;) {
		if(strcmp(ptr->name, name) == 0 && ptr->ipv4 == ipv4_addr) { // Is there a entry (name, ipv4_addr) => Delete
			printk(KERN_INFO "De-Registration Success\n");
			if(ptr == registeredLinkedList) { // do proper process (set proper next) and free
				registeredLinkedList = ptr->next;
				kfree(ptr);				
			} else {
				previous_ptr->next = ptr->next;
				kfree(ptr);
			}
			return set_response_message_header(MSG_DEREGISTER_RESPONSE, MSG_SUCCESS, 4, msg);
		}
		if(ptr->next == NULL) { // => Entry doesn't exists => De-registration error
			break;
		}
		else {
			previous_ptr = ptr;
			ptr = ptr->next;
		}
	}

	printk(KERN_INFO "De-Registration Failed. No entry\n");

	return set_response_message_header(MSG_DEREGISTER_RESPONSE, MSG_FAILED, 4, msg);
}

static unsigned short get_item_from_reg_list(char * data, char * msg) {
	char * name = data;

	struct list_node * ptr = registeredLinkedList;

	printk(KERN_INFO "Entering %s\n", __FUNCTION__);
	printk(KERN_INFO "Traverse table..\n");

	for(; ptr != NULL; ptr = ptr->next) {
		if(strcmp(ptr->name, name) == 0) {
			printk(KERN_INFO "Found!\n");
			set_response_message_header(MSG_GET_RESPONSE, MSG_SUCCESS, 8, msg);
			msg += 4;
			SET_MSG_INTEGER(msg, ptr->ipv4)
			printk(KERN_INFO "Getting data Success\n");
			return 8;
		}
	}

	printk(KERN_INFO "Get data Failed. No entry\n");
	return set_response_message_header(MSG_GET_RESPONSE, MSG_FAILED, 4, msg);
}


static void hello_nl_recv_msg(struct sk_buff *skb) {
	struct nlmsghdr * nlh;
	int pid;
	struct sk_buff * skb_out;
	unsigned short msg_size = 0;
	char msg[200];
	
	char * data;
	int res;

	unsigned char msg_type;
	unsigned short msg_len;

	printk(KERN_ALERT "Entering :%s\n", __FUNCTION__);
		
	nlh = (struct nlmsghdr *)skb->data;
	printk(KERN_INFO "Netlink received msg payload\n");

	data = (char *)nlmsg_data(nlh);
	msg_type = *data;
	data += sizeof(msg_type);
	
	msg_len = *((unsigned short *)data);

	data = data + sizeof(msg_len);

	switch(msg_type) {
	case MSG_REGISTER:
		msg_size = add_item_to_reg_list(data, msg);
		break;
	case MSG_DEREGISTER:
		msg_size = del_item_to_reg_list(data, msg);
		break;
	case MSG_GET:
		msg_size = get_item_from_reg_list(data, msg);
		break;
	}

	pid = nlh->nlmsg_pid; // In nlh, user process id is written. read it.

	skb_out = nlmsg_new(msg_size, 0); // allocate SKB for nlmsghdr + msg size

	if(!skb_out) {
		printk(KERN_ERR "Failed to allocate new skb\n");
		return;
	}

      // put SKB pointer as much as nlmsghdr + msg_size and set up nlmsghdr
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	memcpy(nlmsg_data(nlh), msg, msg_size); // copy message to skb
	res=nlmsg_unicast(nl_sk, skb_out, pid); // send message(skb_out) back to pid, using nl_sk

	if(res < 0) {
		printk(KERN_ERR "Error while sending back to user\n");
	}
}


static int __init hello_init(void) {
	printk(KERN_ALERT "Hello ! I'm 1234 %s\n", __FUNCTION__);

	struct netlink_kernel_cfg cfg = {
		.input = hello_nl_recv_msg,
	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

	if(!nl_sk) {
		printk(KERN_ALERT "Error creating netlink socket\n");
		return -10;
	}

	return 0;
}

static void __exit hello_cleanup(void) {
	printk(KERN_ALERT "Bye !\n");
	netlink_kernel_release(nl_sk);
}

module_init(hello_init);
module_exit(hello_cleanup);