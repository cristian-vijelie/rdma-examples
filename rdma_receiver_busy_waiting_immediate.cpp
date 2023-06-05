#include <cerrno>
#include <memory>
#include <iostream>
#include <string>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>

int main(void)
{
    char write_pipe_name[] = "pipe1", read_pipe_name[] = "pipe2";
    FILE *read_pipe, *write_pipe;

    int num_devices;
    std::unique_ptr<ibv_context, int(*)(ibv_context *)> context { nullptr, nullptr };

    /* Get all RDMA devices on the system */
	std::unique_ptr<ibv_device *, void(*)(ibv_device **)> dev_list { ibv_get_device_list(&num_devices), ibv_free_device_list };
	if (!dev_list)
		return errno;

	for (int i = 0; i < num_devices; i++)
	{
		auto dev = ibv_get_device_name(dev_list.get()[i]);
		if (!dev)
			return errno;

		if (strcmp(dev, "rocep17s0f0") == 0)
		    context = { ibv_open_device(dev_list.get()[i]), ibv_close_device };
	}
	if (!context)
		return errno;

    std::unique_ptr<ibv_pd, int(*)(ibv_pd *)> pd { nullptr, nullptr };

    /* Create the protection domain */
	pd = { ibv_alloc_pd(context.get()), ibv_dealloc_pd };
	if (!pd)
		return errno;

    std::unique_ptr<ibv_cq, int(*)(ibv_cq *)> cq { nullptr, nullptr };

    /* Create the completion queue */
    cq = { ibv_create_cq(context.get(), 0x10, nullptr, nullptr, 0), ibv_destroy_cq };
	if (!cq)
		return errno;

    struct ibv_qp_init_attr qp_init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.recv_cq = cq.get();
	qp_init_attr.send_cq = cq.get();

    /* Use Reliable Connected */
	qp_init_attr.qp_type    = IBV_QPT_RC;
	qp_init_attr.sq_sig_all = 1;

	qp_init_attr.cap.max_send_wr  = 1;
	qp_init_attr.cap.max_recv_wr  = 1;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;

    std::unique_ptr<ibv_qp, int(*)(ibv_qp *)> qp { nullptr, nullptr };

    /* Create the queue pair */
	qp = { ibv_create_qp(pd.get(), &qp_init_attr), ibv_destroy_qp };
	if (!qp)
		return errno;

    struct ibv_qp_attr qp_attr;
	memset(&qp_attr, 0, sizeof(qp_attr));

	qp_attr.qp_state   = ibv_qp_state::IBV_QPS_INIT;
	qp_attr.port_num   = 1;
	qp_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
	                          IBV_ACCESS_REMOTE_WRITE | 
	                          IBV_ACCESS_REMOTE_READ;

	int ret = ibv_modify_qp(qp.get(), &qp_attr,
	                        IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
	if (ret != 0)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
		std::cerr << strerror(ret) << std::endl;
		return ret;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	
	qp_attr.path_mtu              = IBV_MTU_4096;
	qp_attr.qp_state              = ibv_qp_state::IBV_QPS_RTR;
	qp_attr.min_rnr_timer         = 0x12;

    /* RoCEv2 devices require is_global == 1 */
	qp_attr.ah_attr.is_global     = 1;
	qp_attr.ah_attr.port_num      = 1;

    int remote_qp_num;

	read_pipe = fopen(read_pipe_name, "r");
    if (!read_pipe)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
        std::cerr << strerror(errno) << std::endl;
		return errno;
	}

    fread(&remote_qp_num, sizeof(remote_qp_num), 1, read_pipe);
	fclose(read_pipe);

	write_pipe = fopen(write_pipe_name, "w");
    if (!write_pipe)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
        std::cerr << strerror(errno) << std::endl;
		return errno;
	}

	int qp_num = qp->qp_num;

    fwrite(&qp_num, sizeof(qp_num), 1, write_pipe);
	fclose(write_pipe);

    /* 
     * Get the GID of the current device; as both the sender and receiver are on the
     * same interface, source GID and destination GID are the same
     */
	ibv_query_gid(context.get(), 1, 1, &qp_attr.ah_attr.grh.dgid);

	qp_attr.ah_attr.grh.hop_limit     = 5;
	qp_attr.ah_attr.grh.sgid_index    = 1;
	qp_attr.ah_attr.grh.traffic_class = 0;

	qp_attr.ah_attr.dlid = 1;
	qp_attr.dest_qp_num  = remote_qp_num;

	ret = ibv_modify_qp(qp.get(), &qp_attr, IBV_QP_STATE | IBV_QP_AV |
	                    IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
	                    IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);

	if (ret != 0)
	{	
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
		std::cerr << strerror(ret) << std::endl;
		return ret;
	}

    char read_buff[10000];
    memset(read_buff, 'a', sizeof(read_buff));

    auto flags = IBV_ACCESS_LOCAL_WRITE | 
	             IBV_ACCESS_REMOTE_WRITE | 
	             IBV_ACCESS_REMOTE_READ;

    /* Register memory to be used by RDMA operations */
	struct ibv_mr *read_mr = ibv_reg_mr(pd.get(), read_buff, sizeof(read_buff), flags);
	if (!read_mr)
		return errno;

	write_pipe = fopen(write_pipe_name, "w");
    if (!write_pipe)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
        std::cerr << strerror(errno) << std::endl;
		return errno;
	}

    fwrite(read_mr, sizeof(*read_mr), 1, write_pipe);

    char write_buff[10000];
    struct ibv_mr *write_mr = ibv_reg_mr(pd.get(), write_buff, sizeof(write_buff), flags);
	if (!write_mr)
		return errno;

    struct ibv_sge sg_recv;
	struct ibv_recv_wr wr_recv, *bad_wr_recv;

    memset(&sg_recv, 0, sizeof(sg_recv));
	sg_recv.addr   = (uintptr_t)write_mr->addr;
	sg_recv.length = sizeof(write_buff);
	sg_recv.lkey   = write_mr->lkey;

    fwrite(write_mr, sizeof(*write_mr), 1, write_pipe);
	fclose(write_pipe);

	memset(&wr_recv, 0, sizeof(wr_recv));
	wr_recv.wr_id   = 0;
	wr_recv.sg_list = &sg_recv;
	wr_recv.num_sge = 1;

    /*
     * Post a Recv Work Request - we expect data to be sent
     * For a remote application to read, no work request is required from the current application
     */
	ret = ibv_post_recv(qp.get(), &wr_recv, &bad_wr_recv);
	if (ret != 0)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
		return ret;
	}

	ibv_wc wc;

    /* Write with Immediate generates a work completion at the destination when it finishes */
	do
	{
		ret = ibv_poll_cq(cq.get(), 1, &wc);
	} while (ret == 0);
	
	if (ret < 0)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ") " << std::endl;
		return errno;
	}

	if (wc.status != ibv_wc_status::IBV_WC_SUCCESS)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ") " << ibv_wc_status_str(wc.status) << std::endl;
		return -1;
	}

	if ((wc.wc_flags & IBV_WC_WITH_IMM) !=0 && wc.imm_data != ntohl(0x1234))
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ") " << "unexpected immediate data" << std::endl;
		return -1;
	}

    // std::cout << "Write buffer: " << write_buff << std::endl;

    ibv_dereg_mr(read_mr);
    ibv_dereg_mr(write_mr);

	return 0;
}
