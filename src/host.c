#include <linux/inet.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#define PREFIX "cjl RDMA host: "

#define info(fmt, ...) printk(KERN_INFO PREFIX fmt, ##__VA_ARGS__)
#define warn(fmt, ...) printk(KERN_ALERT PREFIX fmt, ##__VA_ARGS__)
#define error(fmt, ...) printk(KERN_ERR PREFIX fmt, ##__VA_ARGS__)

#define RDMA_TIMEOUT 5000
#define PROC_ENTRY_NAME "cjl_rdma_host"

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

static int cjl_cma_event_handler(struct rdma_cm_id *cma_id, struct rdma_cm_event *event)
{
    int ret = 0;
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
        error("RDMA error: %d\n", event->event);
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

static int parse_addr(const char *addr, size_t len, struct sockaddr_in *sin)
{
    char *end = NULL;
    size_t delim_pos = 0;

    int ret = 0;
    while (delim_pos < len && addr[delim_pos] != ':')
    {
        delim_pos++;
    }

    if (delim_pos >= len - 1)
    {
        error("Invalid address: \"%s\"\n", addr);
        ret = -EINVAL;
        goto out;
    }

    if (!in4_pton(addr, delim_pos, host_ctrl->target_addr, -1, &end))
    {
        error("Error parsing address: \"%s\", last char: %c\n", addr, *end);
        ret = -EINVAL;
        goto out;
    }

    ret = kstrtou16(addr + delim_pos + 1, 10, &host_ctrl->target_port);
    if (ret)
    {
        error("Invalid port: \"%s\"\n", addr + delim_pos + 1);
        goto out;
    }

    sin->sin_family = AF_INET;
    memcpy((void *)&sin->sin_addr.s_addr, &host_ctrl->target_addr, 4);
    sin->sin_port = host_ctrl->target_port;

    host_ctrl->target_str = kmalloc(len + 1, GFP_KERNEL);
    if (host_ctrl->target_str == NULL)
    {
        error("Failed to allocate memory for target_str\n");
        ret = -ENOMEM;
        goto out;
    }
    memcpy(host_ctrl->target_str, addr, len);
    host_ctrl->target_str[len] = '\0';

out:
    return ret;
}

static int cjl_rdma_connect(const char *addr, size_t len)
{
    int ret = 0;
    struct sockaddr_in sin;

    ret = parse_addr(addr, len, &sin);
    if (ret)
        goto out;

    info("Connecting to target: %s\n", addr);

    ret = rdma_resolve_addr(host_ctrl->cm_id, NULL, (struct sockaddr *)&sin, RDMA_TIMEOUT);
    if (ret)
        goto resolve_addr_error;
    wait_event_interruptible(host_ctrl->sem, host_ctrl->state >= ADDR_RESOLVED);
    if (host_ctrl->state == ERROR)
        goto resolve_addr_error;
    info("Address resolved\n");

    ret = rdma_resolve_route(host_ctrl->cm_id, RDMA_TIMEOUT);
    if (ret)
        goto resolve_route_error;
    wait_event_interruptible(host_ctrl->sem, host_ctrl->state >= ROUTE_RESOLVED);
    if (host_ctrl->state == ERROR)
        goto resolve_route_error;
    info("Route resolved\n");

out:
    return ret;

resolve_addr_error:
    error("Failed to resolve target addr \"%s\"\n", host_ctrl->target_str);
    return ret ? ret : -1;

resolve_route_error:
    error("Failed to resolve route to target addr \"%s\"\n", host_ctrl->target_str);
    return ret ? ret : -1;
}

static void cjl_rdma_disconnect(void)
{
    kfree(host_ctrl->target_str);
    host_ctrl->state = INITIATED;
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
    size_t pos = 0;

    int ret = 0;
    switch (cmd[pos++])
    {
    case 'c':
        ret = cjl_skip_spaces(cmd + pos, len - pos, &pos);
        if (ret)
        {
            error("Invalid address argument \"%s\" for command \"connect\"\n", cmd + pos);
            break;
        }
        ret = cjl_rdma_connect(cmd + pos, len - pos);
        break;
    case 'r':
        break;
    case 'W':
        break;
    case 'd':
        if (host_ctrl->state == CONNECTED) {
            cjl_rdma_disconnect();
        } else {
            warn("Not connected to any target");
        }
        break;
    default:
        break;
    }

    return ret;
}

static ssize_t proc_entry_read(struct file *__unused, char __user *buff, size_t buff_size, loff_t *ppos)
{
    char *msg;
    ssize_t count = 0;

    int ret = 0;
    if (!try_module_get(THIS_MODULE))
    {
        ret = -ENODEV;
        goto out;
    }

    if (*ppos > 0)
    {
        goto put_module;
    }

    msg = kmalloc(buff_size, GFP_KERNEL);
    if (msg == NULL)
    {
        ret = -ENOMEM;
        goto put_module;
    }

    if (host_ctrl->state == CONNECTED)
    {
        count += sprintf(msg, "Connected to target: %s\n", host_ctrl->target_str);
    }
    else
    {
        count += sprintf(msg, "Not connected to any target\n");
    }

    if (copy_to_user(buff, msg, count))
    {
        error("Failed to copy message to user space!\n");
        ret = -EFAULT;
        goto free_msg;
    }
    *ppos += count;

free_msg:
    kfree(msg);
put_module:
    module_put(THIS_MODULE);
out:
    return count;
}

static ssize_t proc_entry_write(struct file *__unused, const char __user *buff, size_t len, loff_t *ppos)
{
    char *cmd;
    size_t cmd_len = len;

    int ret = 0;
    if (!try_module_get(THIS_MODULE))
    {
        ret = -ENODEV;
        goto out;
    }

    cmd = kmalloc(cmd_len, GFP_KERNEL);
    if (cmd == NULL)
    {
        error("Failed to allocate memory for command!\n");
        ret = -ENOMEM;
        goto put_module;
    }

    if (copy_from_user(cmd, buff, cmd_len))
    {
        error("Failed to copy command to kernel space!\n");
        ret = -EFAULT;
        goto free_cmd;
    }

    if (cmd[cmd_len - 1] == '\n')
    {
        cmd[--cmd_len] = '\0';
    }

    ret = execute_cmd(cmd, cmd_len);

free_cmd:
    kfree(cmd);
put_module:
    module_put(THIS_MODULE);
out:
    return ret ? ret : len;
}

static struct file_operations proc_entry_fops = {
    .owner = THIS_MODULE,
    .read = proc_entry_read,
    .write = proc_entry_write,
};

static int __init host_init(void)
{
    int ret = -ENOMEM;
    host_ctrl = kmalloc(sizeof(*host_ctrl), GFP_KERNEL);
    if (host_ctrl == NULL)
    {
        error("Failed to allocate memory for ctrl!\n");
        goto out;
    }

    memset(host_ctrl, 0, sizeof(*host_ctrl));

    host_ctrl->cm_id = rdma_create_id(&init_net, cjl_cma_event_handler, host_ctrl, RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR_OR_NULL(host_ctrl->cm_id))
    {
        error("Failed to create CM ID: %d\n", PTR_ERR_OR_ZERO(host_ctrl->cm_id));
        ret = PTR_ERR_OR_ZERO(host_ctrl->cm_id);
        goto free_ctrl;
    }

    init_waitqueue_head(&host_ctrl->sem);

    proc_entry = proc_create(PROC_ENTRY_NAME, 0666, NULL, &proc_entry_fops);
    if (proc_entry == NULL)
    {
        info("Failed to create proc entry for host!\n");
        ret = -ENOMEM;
        goto destroy_cm_id;
    }

    return 0;

destroy_cm_id:
    rdma_destroy_id(host_ctrl->cm_id);
free_ctrl:
    kfree(host_ctrl);
out:
    return ret;
}

static void __exit host_exit(void)
{
    remove_proc_entry(PROC_ENTRY_NAME, NULL);
    // FIXME: enable state check after connecting implemented
    // if (host_ctrl->state == CONNECTED)
    // {
    //     cjl_rdma_disconnect();
    // }
    cjl_rdma_disconnect();
    rdma_destroy_id(host_ctrl->cm_id);
    kfree(host_ctrl);
}

module_init(host_init);
module_exit(host_exit);
