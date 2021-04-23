#include <linux/inet.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#define PREFIX "cjl RDMA target: "

#define MAX_ADDR_STR_LEN 24

#define info(fmt, ...) printk(KERN_INFO PREFIX fmt, ##__VA_ARGS__)
#define warn(fmt, ...) printk(KERN_ALERT PREFIX fmt, ##__VA_ARGS__)
#define error(fmt, ...) printk(KERN_ERR PREFIX fmt, ##__VA_ARGS__)

#define RDMA_TIMEOUT 5000
#define PROC_ENTRY_NAME "cjl_rdma_target"

#define CJL_RDMA_BUFF_SIZE 4096
#define CJL_RDMA_MAX_NUM_SG (((CJL_RDMA_BUFF_SIZE - 1) & PAGE_MASK) + PAGE_SIZE) >> PAGE_SHIFT

#define htonll cpu_to_be64
#define ntohll be64_to_cpu

MODULE_AUTHOR("Chen Jinlong");
MODULE_DESCRIPTION("RDMA practice project target module.");
MODULE_LICENSE("GPL v2");

enum cjl_rdma_state
{
    INITIATED,
    CONNECT_REQUEST,
    CONNECTED,
    READ_COMPLETE,
    WRITE_COMPLETE,
    ERROR,
};

struct cjl_rdma_info
{
    uint64_t addr;
    uint32_t size;
    uint32_t rkey;
};

struct cjl_rdma_ctrl
{
    char addr_str[MAX_ADDR_STR_LEN];

    struct ib_qp *qp;
    struct ib_cq *cq;
    struct ib_pd *pd;

    struct rdma_cm_id *cm_id;
    struct rdma_cm_id *conn_cm_id;

    wait_queue_head_t sem;
    enum cjl_rdma_state state;

    struct ib_recv_wr recv_wr;
    struct ib_sge recv_sge;
    struct ib_cqe recv_cqe;
    struct cjl_rdma_info recv_buff __aligned(16);
    u64 recv_dma_addr;

    struct ib_send_wr send_wr;
    struct ib_sge send_sge;
    struct ib_cqe send_cqe;
    struct cjl_rdma_info send_buff __aligned(16);
    u64 send_dma_addr;

    struct ib_reg_wr reg_mr_wr;

    struct ib_rdma_wr rdma_wr;
    struct ib_sge rdma_sge;
    struct ib_cqe rdma_cqe;
    char *rdma_buff;
    u64 rdma_dma_addr;
    struct ib_mr *rdma_mr;
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
    ctrl->cq = NULL;
dealloc_pd:
    ib_dealloc_pd(ctrl->pd);
    ctrl->pd = NULL;
out:
    return ret;
}

static void cjl_rdma_destroy_queues(struct cjl_rdma_ctrl *ctrl)
{
    ib_destroy_qp(ctrl->qp);
    ctrl->qp = NULL;
    ib_destroy_cq(ctrl->cq);
    ctrl->cq = NULL;
    ib_dealloc_pd(ctrl->pd);
    ctrl->pd = NULL;
}

static void cjl_rdma_recv_done(struct ib_cq *cq, struct ib_wc *wc)
{
    struct cjl_rdma_ctrl *ctrl = cq->cq_context;
    info("RECV done: %s (%d)\n", ib_wc_status_msg(wc->status), wc->status);

    if (wc->status == IB_WC_SUCCESS)
    {
        info("Received buff: %llu, rkey: %u, size: %u\n",
             ntohll(ctrl->recv_buff.addr), ntohl(ctrl->recv_buff.rkey), ntohl(ctrl->recv_buff.size));

        ctrl->rdma_wr.remote_addr = ntohll(ctrl->recv_buff.addr);
        ctrl->rdma_wr.rkey = ntohl(ctrl->recv_buff.rkey);
        ctrl->rdma_wr.wr.sg_list->length = ntohl(ctrl->recv_buff.size);
        ctrl->rdma_wr.wr.sg_list->lkey = ctrl->rdma_mr->rkey;
    }
}

static void cjl_rdma_send_done(struct ib_cq *cq, struct ib_wc *wc)
{
    info("SEND done: %s (%d)\n", ib_wc_status_msg(wc->status), wc->status);
}

static void cjl_rdma_rdma_done(struct ib_cq *cq, struct ib_wc *wc)
{
    struct cjl_rdma_ctrl *ctrl = cq->cq_context;

    switch (wc->opcode)
    {
    case IB_WC_RDMA_READ:
        info("READ done: %s (%d)\n", ib_wc_status_msg(wc->status), wc->status);
        ctrl->state = READ_COMPLETE;
        break;
    case IB_WC_RDMA_WRITE:
        info("WRITE done: %s (%d)\n", ib_wc_status_msg(wc->status), wc->status);
        ctrl->state = WRITE_COMPLETE;
        break;
    default:
        error("Unknown RDMA opcode: %d\n", wc->opcode);
        ctrl->state = ERROR;
        break;
    }

    wake_up_interruptible(&ctrl->sem);
}

static void cjl_rdma_setup_wrs(struct cjl_rdma_ctrl *ctrl)
{
    // Setup recv wr.
    ctrl->recv_sge.addr = ctrl->recv_dma_addr;
    ctrl->recv_sge.length = sizeof(ctrl->recv_buff);
    ctrl->recv_sge.lkey = ctrl->pd->local_dma_lkey;
    ctrl->recv_cqe.done = cjl_rdma_recv_done;
    ctrl->recv_wr.wr_cqe = &ctrl->recv_cqe;
    ctrl->recv_wr.sg_list = &ctrl->recv_sge;
    ctrl->recv_wr.num_sge = 1;

    // Setup send wr buff.
    ctrl->send_buff.addr = htonll(ctrl->rdma_dma_addr);
    ctrl->send_buff.rkey = htonl(ctrl->rdma_mr->rkey);
    ctrl->send_buff.size = htonl(CJL_RDMA_BUFF_SIZE);

    // Setup send wr.
    ctrl->send_sge.addr = ctrl->send_dma_addr;
    ctrl->send_sge.length = sizeof(ctrl->send_buff);
    ctrl->send_sge.lkey = ctrl->pd->local_dma_lkey;
    ctrl->send_cqe.done = cjl_rdma_send_done;
    ctrl->send_wr.wr_cqe = &ctrl->send_cqe;
    ctrl->send_wr.opcode = IB_WR_SEND;
    ctrl->send_wr.send_flags = IB_SEND_SIGNALED;
    ctrl->send_wr.sg_list = &ctrl->send_sge;
    ctrl->send_wr.num_sge = 1;

    // Setup register mr wr.
    ctrl->reg_mr_wr.wr.opcode = IB_WR_REG_MR;
    ctrl->reg_mr_wr.mr = ctrl->rdma_mr;
    ctrl->reg_mr_wr.key = ctrl->rdma_mr->rkey;
    ctrl->reg_mr_wr.access = IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_LOCAL_WRITE;

    // Setup RDMA wr.
    ctrl->rdma_sge.addr = ctrl->rdma_dma_addr;
    ctrl->rdma_cqe.done = cjl_rdma_rdma_done;
    ctrl->rdma_wr.wr.wr_cqe = &ctrl->rdma_cqe;
    ctrl->rdma_wr.wr.send_flags = IB_SEND_SIGNALED;
    ctrl->rdma_wr.wr.sg_list = &ctrl->rdma_sge;
    ctrl->rdma_wr.wr.num_sge = 1;
}

static int cjl_rdma_alloc_buffers(struct cjl_rdma_ctrl *ctrl)
{
    int ret = 0;
    struct scatterlist sg = {0};

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

    // Register buffer in Memory Region.
    sg_dma_address(&sg) = ctrl->rdma_dma_addr;
    sg_dma_len(&sg) = CJL_RDMA_BUFF_SIZE;
    ret = ib_map_mr_sg(ctrl->rdma_mr, &sg, 1, NULL, PAGE_SIZE);
    if (ret < 0 || ret > CJL_RDMA_MAX_NUM_SG)
    {
        error("ib_map_mr_sg returned invalid value: %d, should be 0~%lu\n", ret, CJL_RDMA_MAX_NUM_SG);
        goto free_rdma_buff;
    }

    cjl_rdma_setup_wrs(ctrl);

    return 0;

free_rdma_buff:
    ib_dma_free_coherent(ctrl->pd->device, CJL_RDMA_BUFF_SIZE,
                         ctrl->rdma_buff, ctrl->rdma_dma_addr);
    ctrl->rdma_buff = NULL;
unmap:
    ib_dma_unmap_single(ctrl->pd->device, ctrl->recv_dma_addr,
                        sizeof(ctrl->recv_buff), DMA_BIDIRECTIONAL);
    ib_dma_unmap_single(ctrl->pd->device, ctrl->send_dma_addr,
                        sizeof(ctrl->send_buff), DMA_BIDIRECTIONAL);
    return ret;
}

static void cjl_rdma_free_buffers(struct cjl_rdma_ctrl *ctrl)
{
    ib_dereg_mr(ctrl->rdma_mr);
    ctrl->rdma_mr = NULL;
    ib_dma_free_coherent(ctrl->pd->device, CJL_RDMA_BUFF_SIZE,
                         ctrl->rdma_buff, ctrl->rdma_dma_addr);
    ctrl->rdma_buff = NULL;
    ib_dma_unmap_single(ctrl->pd->device, ctrl->recv_dma_addr,
                        sizeof(ctrl->recv_buff), DMA_BIDIRECTIONAL);
    ib_dma_unmap_single(ctrl->pd->device, ctrl->send_dma_addr,
                        sizeof(ctrl->send_buff), DMA_BIDIRECTIONAL);
}

static int cjl_rdma_connect_request(struct cjl_rdma_ctrl *ctrl, struct rdma_cm_event *event)
{
    int ret = 0;
    const struct ib_recv_wr *bad_wr;

    ctrl->state = CONNECT_REQUEST;

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
        goto destroy_queues;
    }

    ret = ib_post_recv(ctrl->qp, &ctrl->recv_wr, &bad_wr);
    if (ret)
    {
        error("Failed to post recv wr\n");
        ctrl->state = ERROR;
        goto free_buffers;
    }

    ret = rdma_accept(ctrl->conn_cm_id, &(event->param.conn));
    if (ret)
    {
        error("Failed to accept host, error code: %d\n", ret);
        ctrl->state = ERROR;
        goto free_buffers;
    }

    return 0;

free_buffers:
    cjl_rdma_free_buffers(ctrl);
destroy_queues:
    cjl_rdma_destroy_queues(ctrl);
out:
    return ret;
}

static int cjl_rdma_connected(struct cjl_rdma_ctrl *ctrl)
{
    int ret = 0;
    const struct ib_send_wr *bad_wr;

    ctrl->state = CONNECTED;

    ret = ib_post_send(ctrl->qp, &ctrl->reg_mr_wr.wr, &bad_wr);
    if (ret)
    {
        error("Failed to post send reg_mr_wr\n");
        goto out;
    }

    ret = ib_post_send(ctrl->qp, &ctrl->send_wr, &bad_wr);
    if (ret)
    {
        error("Failed to post send send_wr\n");
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
        {
            cjl_rdma_free_buffers(ctrl);
            cjl_rdma_destroy_queues(ctrl);
        }
        ctrl->state = ERROR;
        break;
    case RDMA_CM_EVENT_DISCONNECTED:
        error("Unexpected disconnecting: %s (%d)\n", rdma_event_msg(event->event), event->event);
        break;
    default:
        break;
    }

    if (ctrl->state == ERROR)
        wake_up_interruptible(&ctrl->sem);

    return ret;
}

static int parse_addr(const char *addr_str, size_t len, struct sockaddr_in *sin)
{
    u8 addr[4] = {0};
    u16 port = 0;

    const char *end;
    size_t delim_pos = 0;

    int ret = 0;
    while (delim_pos < len && addr_str[delim_pos] != ':')
    {
        delim_pos++;
    }

    if (delim_pos >= len - 1)
    {
        error("Invalid address: \"%s\"\n", addr_str);
        ret = -EINVAL;
        goto out;
    }

    if (!in4_pton(addr_str, delim_pos, addr, -1, &end))
    {
        error("Error parsing address: \"%s\", last char: %c\n", addr_str, *end);
        ret = -EINVAL;
        goto out;
    }

    ret = kstrtou16(addr_str + delim_pos + 1, 10, &port);
    if (ret)
    {
        error("Invalid port: \"%s\"\n", addr_str + delim_pos + 1);
        goto out;
    }

    sin->sin_family = AF_INET;
    memcpy((void *)&sin->sin_addr.s_addr, addr, 4);
    sin->sin_port = port;

    memcpy(target_ctrl->addr_str, addr_str, len);
    target_ctrl->addr_str[len] = '\0';

out:
    return ret;
}

static void cjl_rdma_disconnect(void)
{
    rdma_disconnect(target_ctrl->conn_cm_id);
    cjl_rdma_free_buffers(target_ctrl);
    cjl_rdma_destroy_queues(target_ctrl);
    rdma_destroy_id(target_ctrl->conn_cm_id);
    target_ctrl->state = INITIATED;
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
        error("Failed to bind to addr: %s\n", addr);
        goto out;
    }

    info("Listening at address: %s\n", addr);

    ret = rdma_listen(target_ctrl->cm_id, 128);
    if (ret)
    {
        error("Failed to listen at addr: %s\n", addr);
        goto out;
    }

    ret = wait_event_interruptible(target_ctrl->sem, target_ctrl->state >= CONNECTED);
    if (ret || target_ctrl->state == ERROR)
    {
        error("Failed to accept at: \"%s\"\n", target_ctrl->addr_str);
        goto out;
    }

    info("Host connected\n");

out:
    return ret;
}

static int cjl_rdma_read(struct cjl_rdma_ctrl *ctrl)
{
    int ret = 0;
    const struct ib_send_wr *bad_wr;

    ctrl->rdma_wr.wr.opcode = IB_WR_RDMA_READ;
    ret = ib_post_send(ctrl->qp, &ctrl->rdma_wr.wr, &bad_wr);
    if (ret)
    {
        error("Failed to post rdma read\n");
        goto out;
    }

    ret = wait_event_interruptible(ctrl->sem, ctrl->state >= READ_COMPLETE);
    if (ret || ctrl->state == ERROR)
    {
        error("Failed to read from host\n");
        goto out;
    }

    info("READ from host: %s\n", ctrl->rdma_buff);

out:
    ctrl->state = CONNECTED;
    return ret;
}

static int cjl_rdma_write(struct cjl_rdma_ctrl *ctrl, const char *data, size_t len)
{
    int ret = 0;
    const struct ib_send_wr *bad_wr;

    memcpy(ctrl->rdma_buff, data, len);
    ctrl->rdma_buff[len] = '\0';

    ctrl->rdma_wr.wr.opcode = IB_WR_RDMA_WRITE;
    ret = ib_post_send(ctrl->qp, &ctrl->rdma_wr.wr, &bad_wr);
    if (ret)
    {
        error("Failed to post rdma write\n");
        goto out;
    }

    ret = wait_event_interruptible(ctrl->sem, ctrl->state >= WRITE_COMPLETE);
    if (ret || ctrl->state == ERROR)
    {
        error("Failed to write to host\n");
        goto out;
    }

    info("WRITE to host: %s\n", data);

out:
    ctrl->state = CONNECTED;
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
    case 'l':
        ret = cjl_skip_spaces(cmd + pos, len - pos, &pos);
        if (ret || (len - pos) >= MAX_ADDR_STR_LEN)
        {
            error("Invalid address argument \"%s\" for command \"listen\"\n", cmd + pos);
            break;
        }
        ret = cjl_rdma_accept(cmd + pos, len - pos);
        break;
    case 'r':
        ret = cjl_rdma_read(target_ctrl);
        break;
    case 'w':
        ret = cjl_skip_spaces(cmd + pos, len - pos, &pos);
        if (ret || (len - pos) >= CJL_RDMA_BUFF_SIZE)
        {
            error("Invalid data argument \"%s\" for command \"write\"\n", cmd + pos);
            break;
        }
        ret = cjl_rdma_write(target_ctrl, cmd + pos, len - pos);
        break;
    case 's':
        info("RDMA buffer content: %s\n", target_ctrl->rdma_buff);
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
    if (target_ctrl->state == CONNECTED)
        cjl_rdma_disconnect();
    rdma_destroy_id(target_ctrl->cm_id);
    kfree(target_ctrl);
}

module_init(target_init);
module_exit(target_exit);
