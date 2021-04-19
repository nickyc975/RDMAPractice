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

struct cjl_rdma_info
{
    uint64_t buff;
    uint32_t rkey;
    uint32_t size;
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

    struct ib_recv_wr recv_wr;
    struct ib_sge recv_sge;
    struct cjl_rdma_info recv_buff __aligned(16);
    u64 recv_dma_addr;

    struct ib_send_wr send_wr;
    struct ib_sge send_sge;
    struct cjl_rdma_info send_buff __aligned(16);
    u64 send_dma_addr;

    struct ib_rdma_wr rdma_wr;
    struct ib_sge rdma_sge;
    char *rdma_buff;

#define CJL_RDMA_BUFF_SIZE 4096
#define CJL_RDMA_MAX_NUM_SG (((CJL_RDMA_BUFF_SIZE - 1) & PAGE_MASK) + PAGE_SIZE) >> PAGE_SHIFT

    u64 rdma_dma_addr;
    struct ib_mr *rdma_mr;
};

static struct cjl_rdma_ctrl *host_ctrl;
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

    init_attr.event_handler = cjl_rdma_qp_event_handler;
    init_attr.cap.max_send_wr = 9;
    init_attr.cap.max_recv_wr = 3;
    init_attr.cap.max_recv_sge = 1;
    init_attr.cap.max_send_sge = 1;
    init_attr.qp_type = IB_QPT_RC;
    init_attr.send_cq = ctrl->cq;
    init_attr.recv_cq = ctrl->cq;
    init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

    ret = rdma_create_qp(ctrl->cm_id, ctrl->pd, &init_attr);
    ctrl->qp = ctrl->cm_id->qp;
    return ret;
}

static int cjl_rdma_create_queues(struct cjl_rdma_ctrl *ctrl)
{
    int ret = 0;

    ctrl->pd = ib_alloc_pd(ctrl->cm_id->device, 0);
    if (IS_ERR_OR_NULL(ctrl->pd))
    {
        error("Failed to allocate pd: %d\n", PTR_ERR_OR_ZERO(ctrl->pd));
        ret = PTR_ERR_OR_ZERO(ctrl->pd);
        goto out;
    }

    ctrl->cq = ib_alloc_cq(ctrl->cm_id->device, ctrl, 9, 0, IB_POLL_SOFTIRQ);
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

static void cjl_rdma_destroy_queues(struct cjl_rdma_ctrl *ctrl)
{
    rdma_destroy_qp(ctrl->cm_id);
    ib_destroy_cq(ctrl->cq);
    ib_dealloc_pd(ctrl->pd);
}

static void cjl_rdma_recv_done(struct ib_cq *cq, struct ib_wc *wc)
{
    info("RECV done: %s (%d)\n", ib_wc_status_msg(wc->status), wc->status);
}

static void cjl_rdma_setup_wrs(struct cjl_rdma_ctrl *ctrl)
{
    // Setup recv wr.
    ctrl->recv_sge.addr = ctrl->recv_dma_addr;
    ctrl->recv_sge.length = sizeof(ctrl->recv_buff);
    ctrl->recv_sge.lkey = ctrl->pd->local_dma_lkey;
    ctrl->recv_wr.wr_cqe->done = cjl_rdma_recv_done;
    ctrl->recv_wr.sg_list = &ctrl->recv_sge;
    ctrl->recv_wr.num_sge = 1;

    // Setup send wr.
    ctrl->send_sge.addr = ctrl->send_dma_addr;
    ctrl->send_sge.length = sizeof(ctrl->send_buff);
    ctrl->send_sge.lkey = ctrl->pd->local_dma_lkey;
    ctrl->send_wr.opcode = IB_WR_SEND;
    ctrl->send_wr.send_flags = IB_SEND_SIGNALED;
    ctrl->send_wr.sg_list = &ctrl->send_sge;
    ctrl->send_wr.num_sge = 1;
}

static int cjl_rdma_alloc_buffers(struct cjl_rdma_ctrl *ctrl)
{
    int ret = 0;

    ctrl->recv_dma_addr = ib_dma_map_single(ctrl->pd->device,
                                            &ctrl->recv_buff, sizeof(ctrl->recv_buff), DMA_BIDIRECTIONAL);
    ctrl->send_dma_addr = ib_dma_map_single(ctrl->pd->device,
                                            &ctrl->send_buff, sizeof(ctrl->send_buff), DMA_BIDIRECTIONAL);

    ctrl->rdma_buff = ib_dma_alloc_coherent(ctrl->pd->device,
                                            CJL_RDMA_BUFF_SIZE, &ctrl->rdma_dma_addr, GFP_KERNEL);
    if (ctrl->rdma_buff == NULL)
    {
        error("Failed to allocate memory for rdma_buff\n");
        ret = -ENOMEM;
        goto unmap;
    }

    ctrl->rdma_mr = ib_alloc_mr(ctrl->pd, IB_MR_TYPE_MEM_REG, CJL_RDMA_MAX_NUM_SG);
    if (IS_ERR_OR_NULL(ctrl->rdma_mr))
    {
        error("Failed to register memory region\n");
        ret = PTR_ERR_OR_ZERO(ctrl->rdma_mr);
        goto free_rdma_buff;
    }

    cjl_rdma_setup_wrs(ctrl);

    return 0;

free_rdma_buff:
    ib_dma_free_coherent(ctrl->pd->device, CJL_RDMA_BUFF_SIZE,
                         ctrl->rdma_buff, ctrl->rdma_dma_addr);
unmap:
    ib_dma_unmap_single(ctrl->pd->device, ctrl->recv_dma_addr,
                        sizeof(ctrl->recv_buff), DMA_BIDIRECTIONAL);
    ib_dma_unmap_single(ctrl->pd->device, ctrl->send_dma_addr,
                        sizeof(ctrl->send_buff), DMA_BIDIRECTIONAL);
    return ret;
}

static void cjl_rdma_free_buffers(struct cjl_rdma_ctrl *ctrl)
{
    ib_dma_free_coherent(ctrl->pd->device, CJL_RDMA_BUFF_SIZE,
                         ctrl->rdma_buff, ctrl->rdma_dma_addr);
    ib_dma_unmap_single(ctrl->pd->device, ctrl->recv_dma_addr,
                        sizeof(ctrl->recv_buff), DMA_BIDIRECTIONAL);
    ib_dma_unmap_single(ctrl->pd->device, ctrl->send_dma_addr,
                        sizeof(ctrl->send_buff), DMA_BIDIRECTIONAL);
}

static int cjl_rdma_addr_resolved(struct cjl_rdma_ctrl *ctrl)
{
    int ret;
    ctrl->state = ADDR_RESOLVED;

    ret = cjl_rdma_create_queues(ctrl);
    if (ret)
    {
        error("Failed to create queues for ctrl\n");
        ctrl->state = ERROR;
        goto out;
    }

    ret = cjl_rdma_alloc_buffers(ctrl);
    if (ret)
    {
        error("Failed to setup buffers\n");
        ctrl->state = ERROR;
        goto out;
    }

    ret = rdma_resolve_route(ctrl->cm_id, RDMA_TIMEOUT);
    if (ret)
    {
        error("Failed to resolve route to target: \"%s\"\n", ctrl->target_str);
        cjl_rdma_destroy_queues(ctrl);
        ctrl->state = ERROR;
    }

out:
    return ret;
}

static int cjl_rdma_route_resolved(struct cjl_rdma_ctrl *ctrl)
{
    int ret = 0;
    struct rdma_conn_param param;

    ctrl->state = ROUTE_RESOLVED;

    memset(&param, 0, sizeof(param));
    param.responder_resources = 1;
    param.initiator_depth = 1;
    param.retry_count = 5;
    param.qp_num = ctrl->qp->qp_num;
    param.flow_control = 1;

    ret = rdma_connect(ctrl->cm_id, &param);
    if (ret)
    {
        error("Failed to connect to target: \"%s\"\n", ctrl->target_str);
        cjl_rdma_destroy_queues(ctrl);
        ctrl->state = ERROR;
    }

    return ret;
}

static int cjl_rdma_connected(struct cjl_rdma_ctrl *ctrl)
{
    int ret = 0;
    const struct ib_recv_wr *bad_wr;

    ctrl->state = CONNECTED;
    ret = ib_post_recv(ctrl->qp, &ctrl->recv_wr, &bad_wr);
    if (ret)
    {
        error("Failed to post recv wr\n");
        goto out;
    }

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
    case RDMA_CM_EVENT_ADDR_RESOLVED:
        ret = cjl_rdma_addr_resolved(ctrl);
        break;
    case RDMA_CM_EVENT_ROUTE_RESOLVED:
        ret = cjl_rdma_route_resolved(ctrl);
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
        if (ctrl->state >= ADDR_RESOLVED && ctrl->state < ERROR)
        {
            cjl_rdma_free_buffers(ctrl);
            cjl_rdma_destroy_queues(ctrl);
        }
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
    const char *end;
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

static void cjl_rdma_disconnect(void)
{
    rdma_disconnect(host_ctrl->cm_id);
    cjl_rdma_free_buffers(host_ctrl);
    cjl_rdma_destroy_queues(host_ctrl);
    kfree(host_ctrl->target_str);
    host_ctrl->state = INITIATED;
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
    {
        error("Failed to resolve target address: \"%s\"\n", host_ctrl->target_str);
        goto out;
    }

    ret = wait_event_interruptible(host_ctrl->sem, host_ctrl->state >= CONNECTED);
    if (ret || host_ctrl->state == ERROR)
    {
        error("Failed to connect to target: \"%s\"\n", host_ctrl->target_str);
        goto out;
    }

    info("Connected to target: %s\n", addr);

    // FIXME: remove this after debugging.
    cjl_rdma_disconnect();

out:
    return ret;
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
        if (host_ctrl->state == CONNECTED)
            cjl_rdma_disconnect();
        else
            warn("Not connected to any target");
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

    host_ctrl->cm_id = rdma_create_id(&init_net, cjl_rdma_cma_event_handler, host_ctrl, RDMA_PS_TCP, IB_QPT_RC);
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
    if (host_ctrl->state == CONNECTED)
        cjl_rdma_disconnect();
    rdma_destroy_id(host_ctrl->cm_id);
    kfree(host_ctrl);
}

module_init(host_init);
module_exit(host_exit);
