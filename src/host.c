#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

MODULE_AUTHOR("Chen Jinlong");
MODULE_DESCRIPTION("RDMA practice project host module.");
MODULE_LICENSE("GPL v2");

static struct proc_dir_entry *proc_entry;

struct cjl_rdma_ctrl
{
    int connected;
    char *target_addr;
    int target_port;

    struct ib_qp *qp;
    struct ib_cq *cq;
    struct ib_pd *pd;

    struct rdma_cm_id *cm_id;
};

static struct cjl_rdma_ctrl *host_ctrl;

// static int cjl_rdma_connect()
// {
// }

// static int cjl_rdma_read()
// {
// }

// static int cjl_rdma_write()
// {
// }

// static int cjl_rdma_disconnect()
// {
// }

static int execute_cmd(const char *cmd, size_t len)
{
    size_t pos = len;
    if (len < 1)
    {
        return 0;
    }

    switch (cmd[pos])
    {
    case 'c':
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

    return 0;
}

static ssize_t proc_read(struct file *__unused, char __user *buff, size_t buff_size, loff_t *ppos)
{
    char *msg;
    ssize_t count = 0;

    if (!try_module_get(THIS_MODULE))
    {
        return -ENODEV;
    }

    if (*ppos > 0)
    {
        return 0;
    }

    msg = kmalloc(buff_size, GFP_KERNEL);
    if (msg == NULL) {
        return -ENOMEM;
    }

    memset(msg, 0, buff_size);

    if (host_ctrl->connected)
    {
        count += sprintf(msg, "Connected to target %s:%d\n", host_ctrl->target_addr, host_ctrl->target_port);
    }
    else
    {
        count += sprintf(msg, "Not connected to any target\n");
    }

    if (copy_to_user(buff, msg, count))
    {
        printk(KERN_ERR "Failed to copy command!\n");
        kfree(msg);
        return -EFAULT;
    }

    kfree(msg);
    *ppos = count;
    module_put(THIS_MODULE);
    return count;
}

static ssize_t proc_write(struct file * __unused, const char __user *buff, size_t len, loff_t *ppos)
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
    // if (host_ctrl->connected) {
    //     cjl_rdma_disconnect(host_ctrl);
    // }
    kfree(host_ctrl);
}

module_init(host_init);
module_exit(host_exit);
