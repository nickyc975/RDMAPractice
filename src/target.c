#include <linux/init.h>
#include <linux/module.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

static struct proc_dir_entry *proc_entry;

struct cjl_rdma_ctrl {
    int connected;

    struct ib_qp *qp;
    struct ib_cq *cq;
    struct ib_pd *pd;

    struct rdma_cm_id *cm_id;
};

static int cjl_rdma_listen(struct cjl_rdma_ctrl *ctrl) {

}

static int cjl_rdma_accept(struct cjl_rdma_ctrl *ctrl) {

}
