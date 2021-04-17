#include <linux/inet.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#define PREFIX "cjl RDMA target: "

#define info(fmt, ...) printk(KERN_INFO PREFIX fmt, ##__VA_ARGS__)
#define warn(fmt, ...) printk(KERN_ALERT PREFIX fmt, ##__VA_ARGS__)
#define error(fmt, ...) printk(KERN_ERR PREFIX fmt, ##__VA_ARGS__)

#define RDMA_TIMEOUT 5000
#define PROC_ENTRY_NAME "cjl_rdma_target"

MODULE_AUTHOR("Chen Jinlong");
MODULE_DESCRIPTION("RDMA practice project target module.");
MODULE_LICENSE("GPL v2");

enum cjl_rdma_state
{
    INITIATED,
    CONNECT_REQUEST,
    CONNECTED,
    ERROR,
};

struct cjl_rdma_ctrl
{
    char *addr_str;
    u8 addr[4];
    u16 port;

    struct ib_qp *qp;
    struct ib_cq *cq;
    struct ib_pd *pd;

    struct rdma_cm_id *cm_id;
    struct rdma_cm_id *conn_cm_id;

    wait_queue_head_t sem;
    enum cjl_rdma_state state;
};

static struct cjl_rdma_ctrl *target_ctrl;
static struct proc_dir_entry *proc_entry;

static void cjl_rdma_qp_event_handler(struct ib_event *event, void *__unused)
{
    info("QP event %s (%d)\n", ib_event_msg(event->event), event->event);
}

static int cjl_rdma_create_qp(struct cjl_rdma_ctrl *ctrl)
{
    int ret;
    struct ib_qp_init_attr init_attr;

    memset(&init_attr, 0, sizeof(init_attr));

    init_attr.qp_context = ctrl;
    init_attr.event_handler = cjl_rdma_qp_event_handler;
    init_attr.cap.max_send_wr = 9;
    init_attr.cap.max_recv_wr = 3;
    init_attr.cap.max_recv_sge = 1;
    init_attr.cap.max_send_sge = 1;
    init_attr.qp_type = IB_QPT_RC;
    init_attr.send_cq = ctrl->cq;
    init_attr.recv_cq = ctrl->cq;
    init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

    ret = rdma_create_qp(ctrl->conn_cm_id, ctrl->pd, &init_attr);
    ctrl->qp = ctrl->conn_cm_id->qp;
    return ret;
}

static int cjl_rdma_create_queues(struct cjl_rdma_ctrl *ctrl)
{
    int ret = 0;

    ctrl->pd = ib_alloc_pd(ctrl->conn_cm_id->device, 0);
    if (IS_ERR_OR_NULL(ctrl->pd))
    {
        error("Failed to allocate pd: %d\n", PTR_ERR_OR_ZERO(ctrl->pd));
        ret = PTR_ERR_OR_ZERO(ctrl->pd);
        goto out;
    }

    ctrl->cq = ib_alloc_cq(ctrl->conn_cm_id->device, ctrl, 9, 1, IB_POLL_SOFTIRQ);
    if (IS_ERR_OR_NULL(ctrl->cq))
    {
        error("Failed to allocate pd: %d\n", PTR_ERR_OR_ZERO(ctrl->cq));
        ret = PTR_ERR_OR_ZERO(ctrl->cq);
        goto dealloc_pd;
    }

    ret = cjl_rdma_create_qp(ctrl);
    if (ret)
    {
        error("Failed to create qp, error code: %d\n", ret);
        goto destroy_cq;
    }

    return 0;

destroy_cq:
    ib_destroy_cq(ctrl->cq);
dealloc_pd:
    ib_dealloc_pd(ctrl->pd);
out:
    return ret;
}

static void cjl_rdma_destroy_queues(struct cjl_rdma_ctrl *ctrl) {
    rdma_destroy_qp(ctrl->conn_cm_id);
    ib_destroy_cq(ctrl->cq);
    ib_dealloc_pd(ctrl->pd);
}

static int cjl_rdma_connect_request(struct cjl_rdma_ctrl *ctrl, struct rdma_cm_event *event) {
    int ret = 0;
    ctrl->state = CONNECT_REQUEST;

    ret = cjl_rdma_create_queues(ctrl);
    if (ret)
    {
        error("Failed to create queues for ctrl\n");
        ctrl->state = ERROR;
        goto out;
    }

    ret = rdma_accept(ctrl->conn_cm_id, &(event->param.conn));
    if (ret)
    {
        error("Failed to accept host, error code: %d\n", ret);
        cjl_rdma_destroy_queues(ctrl);
        ctrl->state = ERROR;
    }

out:
    return ret;
}

static void cjl_rdma_recv_done(struct ib_cq *cq, struct ib_wc *wc)
{
    info("RECV done: %s (%d)\n", ib_wc_status_msg(wc->status), wc->status);
}

static int cjl_rdma_connected(struct cjl_rdma_ctrl *ctrl)
{
    int ret = 0;
    // struct ib_recv_wr recv_wr, *bad_wr;

    ctrl->state = CONNECTED;

    // memset(&recv_wr, 0, sizeof(recv_wr));
    // recv_wr.wr_cqe->done = cjl_rdma_recv_done;
    // ret = ib_post_recv(ctrl->qp, &recv_wr, &bad_wr);
    // if (ret)
    // {
    //     error("Failed to post recv wr\n");
    //     cjl_rdma_destroy_queues(ctrl);
    //     ctrl->state = ERROR;
    //     goto out;
    // }

    wake_up_interruptible(&ctrl->sem);

out:
    return ret;
}

static int cjl_rdma_cma_event_handler(struct rdma_cm_id *cma_id, struct rdma_cm_event *event)
{
    int ret = 0;
    struct cjl_rdma_ctrl *ctrl = cma_id->context;

    switch (event->event)
    {
    case RDMA_CM_EVENT_CONNECT_REQUEST:
        ctrl->conn_cm_id = cma_id;
        ret = cjl_rdma_connect_request(ctrl, event);
        break;
    case RDMA_CM_EVENT_ESTABLISHED:
        ret = cjl_rdma_connected(ctrl);
        break;
    case RDMA_CM_EVENT_ADDR_ERROR:
    case RDMA_CM_EVENT_ROUTE_ERROR:
    case RDMA_CM_EVENT_CONNECT_ERROR:
    case RDMA_CM_EVENT_UNREACHABLE:
    case RDMA_CM_EVENT_REJECTED:
        error("RDMA_CM_EVENT_ERROR: %s (%d)\n", rdma_event_msg(event->event), event->event);
        if (ctrl->state >= CONNECT_REQUEST && ctrl->state < ERROR)
            cjl_rdma_destroy_queues(ctrl);
        ctrl->state = ERROR;
        break;
    case RDMA_CM_EVENT_DISCONNECTED:
        break;
    default:
        break;
    }

    if (ctrl->state == ERROR)
        wake_up_interruptible(&ctrl->sem);

    return ret;
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

    if (!in4_pton(addr, delim_pos, target_ctrl->addr, -1, &end))
    {
        error("Error parsing address: \"%s\", last char: %c\n", addr, *end);
        ret = -EINVAL;
        goto out;
    }

    ret = kstrtou16(addr + delim_pos + 1, 10, &target_ctrl->port);
    if (ret)
    {
        error("Invalid port: \"%s\"\n", addr + delim_pos + 1);
        goto out;
    }

    sin->sin_family = AF_INET;
    memcpy((void *)&sin->sin_addr.s_addr, &target_ctrl->addr, 4);
    sin->sin_port = target_ctrl->port;

    target_ctrl->addr_str = kmalloc(len + 1, GFP_KERNEL);
    if (target_ctrl->addr_str == NULL)
    {
        error("Failed to allocate memory for addr_str\n");
        ret = -ENOMEM;
        goto out;
    }
    memcpy(target_ctrl->addr_str, addr, len);
    target_ctrl->addr_str[len] = '\0';

out:
    return ret;
}


static int cjl_rdma_accept(const char *addr, size_t len)
{
    int ret = 0;
    struct sockaddr_in sin;

    ret = parse_addr(addr, len, &sin);
    if (ret)
        goto out;

    ret = rdma_bind_addr(target_ctrl->cm_id, (struct sockaddr *)&sin);
    if (ret)
    {
        error("Failed to bind to addr: %s\n", target_ctrl->addr);
        goto out;
    }

    info("Listening at address: %s\n", addr);

    ret = rdma_listen(target_ctrl->cm_id, 128);
    if (ret)
    {
        error("Failed to listen at addr: %s\n", target_ctrl->addr);
        goto out;
    }

    ret = wait_event_interruptible(target_ctrl->sem, target_ctrl->state >= CONNECTED);
	if (ret || target_ctrl->state == ERROR) {
		error("Failed to accept at: \"%s\"\n", target_ctrl->addr_str);
		goto out;
	}

    info("Host connected\n");

    // FIXME: remove this after debugging.
    // cjl_rdma_destroy_queues(target_ctrl);

out:
    return ret;
}

static void cjl_rdma_disconnect(void)
{
    kfree(target_ctrl->addr_str);
    target_ctrl->state = INITIATED;
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
    case 'l':
        ret = cjl_skip_spaces(cmd + pos, len - pos, &pos);
        if (ret)
        {
            error("Invalid address argument \"%s\" for command \"listen\"\n", cmd + pos);
            break;
        }
        ret = cjl_rdma_accept(cmd + pos, len - pos);
        break;
    case 'r':
        break;
    case 'W':
        break;
    case 'd':
        if (target_ctrl->state == CONNECTED)
            cjl_rdma_disconnect();
        else
            warn("Not connected");
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

    if (target_ctrl->state == CONNECTED)
    {
        count += sprintf(msg, "Connected with host\n");
    }
    else
    {
        count += sprintf(msg, "Not connected\n");
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

static int __init target_init(void)
{
    int ret = -ENOMEM;
    target_ctrl = kmalloc(sizeof(*target_ctrl), GFP_KERNEL);
    if (target_ctrl == NULL)
    {
        error("Failed to allocate memory for ctrl!\n");
        goto out;
    }

    memset(target_ctrl, 0, sizeof(*target_ctrl));

    target_ctrl->cm_id = rdma_create_id(&init_net, cjl_rdma_cma_event_handler, target_ctrl, RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR_OR_NULL(target_ctrl->cm_id))
    {
        error("Failed to create CM ID: %d\n", PTR_ERR_OR_ZERO(target_ctrl->cm_id));
        ret = PTR_ERR_OR_ZERO(target_ctrl->cm_id);
        goto free_ctrl;
    }

    init_waitqueue_head(&target_ctrl->sem);

    proc_entry = proc_create(PROC_ENTRY_NAME, 0666, NULL, &proc_entry_fops);
    if (proc_entry == NULL)
    {
        info("Failed to create proc entry for target!\n");
        ret = -ENOMEM;
        goto destroy_cm_id;
    }

    return 0;

destroy_cm_id:
    rdma_destroy_id(target_ctrl->cm_id);
free_ctrl:
    kfree(target_ctrl);
out:
    return ret;
}

static void __exit target_exit(void)
{
    remove_proc_entry(PROC_ENTRY_NAME, NULL);
    // FIXME: enable state check after connecting implemented
    // if (target_ctrl->state == CONNECTED)
    // {
    //     cjl_rdma_disconnect();
    // }
    cjl_rdma_disconnect();
    rdma_destroy_id(target_ctrl->cm_id);
    kfree(target_ctrl);
}

module_init(target_init);
module_exit(target_exit);
