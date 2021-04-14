#include <linux/inet.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

MODULE_AUTHOR("Chen Jinlong");
MODULE_DESCRIPTION("RDMA practice project host module.");
MODULE_LICENSE("GPL v2");

enum cjl_rdma_state
{
    INITIATED,
    ADDR_RESOLVED,
    ROUTE_RESOLVED,
    CONNECTED,
    ERROR,
};

struct cjl_rdma_ctrl
{
    int connected;
    char *target_str;
    u8 target_addr[4];
    u16 target_port;

    struct ib_qp *qp;
    struct ib_cq *cq;
    struct ib_pd *pd;

    struct rdma_cm_id *cm_id;

    wait_queue_head_t sem;
    enum cjl_rdma_state state;
};

static struct cjl_rdma_ctrl *host_ctrl;
static struct proc_dir_entry *proc_entry;

static int parse_addr(const char *addr, size_t len, struct sockaddr_in *sin)
{
    char *end = NULL;
    int res = 0;
    size_t delim_pos = 0;
    while (delim_pos < len && addr[delim_pos] != ':')
    {
        delim_pos++;
    }

    if (delim_pos >= len - 1)
    {
        printk(KERN_ERR "invalid address: \"%s\"\n", addr);
        res = -EINVAL;
        goto out;
    }

    res = kstrtou16(addr + delim_pos + 1, 10, &host_ctrl->target_port);
    if (res)
    {
        printk(KERN_ERR "invalid port: \"%s\"\n", addr + delim_pos + 1);
        goto out;
    }

    if (!in4_pton(addr, delim_pos, host_ctrl->target_addr, -1, &end))
    {
        printk(KERN_ERR "invalid address: \"%s\", last char: %c\n", addr, *end);
        res = -EINVAL;
        goto out;
    }

    sin->sin_family = AF_INET;
    memcpy((void *)&sin->sin_addr.s_addr, &host_ctrl->target_addr, 4);
    sin->sin_port = host_ctrl->target_port;

    host_ctrl->target_str = kmalloc(len + 1, GFP_KERNEL);
    if (host_ctrl->target_str == NULL)
    {
        res = -ENOMEM;
        goto out;
    }
    memcpy(host_ctrl->target_str, addr, len);
    host_ctrl->target_str[len] = '\0';

out:
    return res;
}

static int cjl_rdma_connect(const char *addr, size_t len)
{
    int res = 0;
    struct sockaddr_in sin;

    res = parse_addr(addr, len, &sin);
    if (res)
        goto out;

    res = rdma_resolve_addr(host_ctrl->cm_id, NULL, (struct sockaddr *)&sin, 5000);
    if (res)
        goto resolve_addr_error;
    wait_event_interruptible(host_ctrl->sem, host_ctrl->state >= ADDR_RESOLVED);
    if (host_ctrl->state == ERROR)
        goto resolve_addr_error;
    printk(KERN_INFO "addr resolved\n");

    res = rdma_resolve_route(host_ctrl->cm_id, 5000);
    if (res)
        goto resolve_route_error;
    wait_event_interruptible(host_ctrl->sem, host_ctrl->state >= ROUTE_RESOLVED);
    if (host_ctrl->state == ERROR)
        goto resolve_route_error;
    printk(KERN_INFO "route resolved\n");

out:
    return res;

resolve_addr_error:
    printk(KERN_ERR "Failed to resolve target addr \"%s\"\n", host_ctrl->target_str);
    return res ? res : -1;

resolve_route_error:
    printk(KERN_ERR "Failed to resolve route to target addr \"%s\"\n", host_ctrl->target_str);
    return res ? res : -1;
}

static void cjl_rdma_disconnect(void)
{
    kfree(host_ctrl->target_str);
    return;
}

static inline int cjl_skip_spaces(const char *str, size_t len, size_t *ppos)
{
    size_t pos = 0;
    while (pos < len && str[pos] == ' ')
        pos++;
    if (str[pos] == '\0' || pos >= len)
    {
        return -EINVAL;
    }
    *ppos += pos;
    return 0;
}

static int execute_cmd(const char *cmd, size_t len)
{
    char *arg;
    size_t pos = 0;

    int res = 0;
    switch (cmd[pos++])
    {
    case 'c':
        res = cjl_skip_spaces(cmd + pos, len - pos, &pos);
        if (res)
        {
            printk(KERN_ERR "invalid address argument \"%s\" for command \"connect\"\n", cmd + pos);
            break;
        }
        printk(KERN_INFO "connecting to %s\n", cmd + pos);
        res = cjl_rdma_connect(cmd + pos, len - pos);
        break;
    case 'r':
        break;
    case 'W':
        break;
    case 'd':
        break;
    default:
        break;
    }

    return res;
}

static ssize_t proc_read(struct file *__unused, char __user *buff, size_t buff_size, loff_t *ppos)
{
    char *msg;
    ssize_t count = 0;

    int res = 0;
    if (!try_module_get(THIS_MODULE))
    {
        res = -ENODEV;
        goto out;
    }

    if (*ppos > 0)
        goto out_put_module;

    msg = kmalloc(buff_size, GFP_KERNEL);
    if (msg == NULL)
    {
        res = -ENOMEM;
        goto out_put_module;
    }

    memset(msg, 0, buff_size);

    if (host_ctrl->connected)
    {
        count += sprintf(msg, "Connected to target %s:%d\n", host_ctrl->target_str, host_ctrl->target_port);
    }
    else
    {
        count += sprintf(msg, "Not connected to any target\n");
    }

    if (copy_to_user(buff, msg, count))
    {
        printk(KERN_ERR "Failed to copy command!\n");
        res = -EFAULT;
        goto out_free_msg;
    }
    *ppos = count;

out_free_msg:
    kfree(msg);
out_put_module:
    module_put(THIS_MODULE);
out:
    return count;
}

static ssize_t proc_write(struct file *__unused, const char __user *buff, size_t len, loff_t *ppos)
{
    char *cmd;
    int res = len, tmp;

    if (!try_module_get(THIS_MODULE))
    {
        res = -ENODEV;
        goto fail;
    }

    cmd = kmalloc(len, GFP_KERNEL);
    if (cmd == NULL)
    {
        printk(KERN_ERR "Failed to allocate memory!\n");
        res = -ENOMEM;
        goto fail_put_module;
    }

    if (copy_from_user(cmd, buff, len))
    {
        printk(KERN_ERR "Failed to copy command!\n");
        res = -EFAULT;
        goto fail_free_cmd;
    }

    if (cmd[len - 1] == '\n')
    {
        cmd[--len] = '\0';
    }

    tmp = execute_cmd(cmd, len);
    res = tmp ? tmp : res;

fail_free_cmd:
    kfree(cmd);
fail_put_module:
    module_put(THIS_MODULE);
fail:
    return res;
}

static struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .read = proc_read,
    .write = proc_write,
};

static int cjl_cma_event_handler(struct rdma_cm_id *cma_id, struct rdma_cm_event *event)
{
    int res = 0;
    struct cjl_rdma_ctrl *ctrl = cma_id->context;

    switch (event->event)
    {
    case RDMA_CM_EVENT_ADDR_RESOLVED:
        ctrl->state = ADDR_RESOLVED;
        wake_up_interruptible(&ctrl->sem);
        break;
    case RDMA_CM_EVENT_ROUTE_RESOLVED:
        ctrl->state = ROUTE_RESOLVED;
        wake_up_interruptible(&ctrl->sem);
        break;
    case RDMA_CM_EVENT_ESTABLISHED:
        ctrl->state = CONNECTED;
        wake_up_interruptible(&ctrl->sem);
        break;
    case RDMA_CM_EVENT_ADDR_ERROR:
    case RDMA_CM_EVENT_ROUTE_ERROR:
    case RDMA_CM_EVENT_CONNECT_ERROR:
    case RDMA_CM_EVENT_UNREACHABLE:
    case RDMA_CM_EVENT_REJECTED:
        printk(KERN_ERR "RDMA error: %d\n", event->event);
        ctrl->state = ERROR;
        wake_up_interruptible(&ctrl->sem);
        break;
    case RDMA_CM_EVENT_DISCONNECTED:
        break;
    default:
        break;
    }
    return 0;
}

static int __init host_init(void)
{
    int res = 0;
    host_ctrl = kmalloc(sizeof(*host_ctrl), GFP_KERNEL);
    if (host_ctrl == NULL)
    {
        printk(KERN_ERR "Failed to allocate memory!\n");
        res = -ENOMEM;
        goto done;
    }

    memset(host_ctrl, 0, sizeof(*host_ctrl));
    host_ctrl->cm_id = rdma_create_id(&init_net, cjl_cma_event_handler, host_ctrl, RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR_OR_NULL(host_ctrl->cm_id))
    {
        printk(KERN_ERR "failed to create CM ID: %ld\n", PTR_ERR_OR_ZERO(host_ctrl->cm_id));
        res = PTR_ERR_OR_ZERO(host_ctrl->cm_id);
        goto fail;
    }

    init_waitqueue_head(&host_ctrl->sem);

    proc_entry = proc_create("cjl_rdma_host", 0666, NULL, &proc_fops);
    if (proc_entry == NULL)
    {
        printk(KERN_INFO "Failed to create proc entry for host!\n");
        res = -ENOMEM;
        goto fail;
    }
    goto done;

fail:
    kfree(host_ctrl);
done:
    return res;
}

static void __exit host_exit(void)
{
    remove_proc_entry("cjl_rdma_host", NULL);
    if (host_ctrl->connected)
    {
        cjl_rdma_disconnect();
    }
    rdma_destroy_id(host_ctrl->cm_id);
    kfree(host_ctrl);
}

module_init(host_init);
module_exit(host_exit);
