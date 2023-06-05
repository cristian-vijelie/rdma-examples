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
    char read_pipe_name[] = "pipe1", write_pipe_name[] = "pipe2";
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
		{
			context = { ibv_open_device(dev_list.get()[i]), ibv_close_device };
			break;
		}
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
	qp_attr.pkey_index = 0;
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

    int qp_num = qp->qp_num;

    write_pipe = fopen(write_pipe_name, "w");
    if (!write_pipe)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
        std::cerr << strerror(errno) << std::endl;
		return errno;
	}

    fwrite(&qp_num, sizeof(qp_num), 1, write_pipe);
    fclose(write_pipe);

    read_pipe = fopen(read_pipe_name, "r");
    if (!read_pipe)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
        std::cerr << strerror(errno) << std::endl;
		return errno;
	}

    int remote_qp_num;

    fread(&remote_qp_num, sizeof(remote_qp_num), 1, read_pipe);
    fclose(read_pipe);

    /* 
     * Get the GID of the current device; as both the sender and receiver are on the
     * same interface, source GID and destination GID are the same
     */
	ibv_query_gid(context.get(), 1, 1, &qp_attr.ah_attr.grh.dgid);
	
	qp_attr.ah_attr.grh.hop_limit     = 5;
	qp_attr.ah_attr.grh.sgid_index    = 1;

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

	qp_attr.qp_state      = ibv_qp_state::IBV_QPS_RTS;
    qp_attr.timeout       = 18;
    qp_attr.retry_cnt     = 7;
    qp_attr.rnr_retry     = 7;

    ret = ibv_modify_qp(qp.get(), &qp_attr, IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                        IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC);
    if (ret != 0)
    {	
        std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
        std::cerr << strerror(ret) << std::endl;
        return ret;
    }

    char read_buff[10000];
    auto flags = IBV_ACCESS_LOCAL_WRITE | 
	             IBV_ACCESS_REMOTE_WRITE | 
	             IBV_ACCESS_REMOTE_READ;

    /* Register memory to be used by RDMA operations */
	struct ibv_mr *read_mr = ibv_reg_mr(pd.get(), read_buff, sizeof(read_buff), flags);
	if (!read_mr)
		return errno;

    struct ibv_sge sg_read;
	struct ibv_send_wr wr_read, *bad_wr_read;

	memset(&sg_read, 0, sizeof(sg_read));
	sg_read.addr   = (uintptr_t)read_mr->addr;
	sg_read.length = sizeof(read_buff);
	sg_read.lkey   = read_mr->lkey;

    read_pipe = fopen(read_pipe_name, "r");
    if (!read_pipe)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
        std::cerr << strerror(errno) << std::endl;
		return errno;
	}

    ibv_mr remote_read_mr;
    fread(&remote_read_mr, sizeof(remote_read_mr), 1, read_pipe);

	memset(&wr_read, 0, sizeof(wr_read));
	wr_read.sg_list             = &sg_read;
	wr_read.num_sge             = 1;
	wr_read.opcode              = IBV_WR_RDMA_READ;
	wr_read.send_flags          = IBV_SEND_SIGNALED;
    wr_read.wr.rdma.remote_addr = (uintptr_t)remote_read_mr.addr;
    wr_read.wr.rdma.rkey        = remote_read_mr.rkey;

    /* Initiate a Read operation */
	ret = ibv_post_send(qp.get(), &wr_read, &bad_wr_read);
	if (ret != 0)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
		return ret;
	}

    ibv_wc wc;

    /*
     * The initiated operation generates a Work Completion, that is consumed.
     * That way, the application ensures the data is valid.
     */
    do
	{
		ret = ibv_poll_cq(cq.get(), 1, &wc);
	} while (ret == 0);

    // std::cout << "Read buffer: " << read_buff << std::endl;

    char write_buff[10000];
    memset(write_buff, 'b', sizeof(write_buff));

    struct ibv_mr *write_mr = ibv_reg_mr(pd.get(), write_buff, sizeof(write_buff), flags);
	if (!write_mr)
		return errno;

    struct ibv_sge sg_write;
	struct ibv_send_wr wr_write, *bad_wr_write;

    memset(&sg_write, 0, sizeof(sg_write));
	sg_write.addr   = (uintptr_t)write_mr->addr;
	sg_write.length = sizeof(write_buff);
	sg_write.lkey   = write_mr->lkey;

    ibv_mr remote_write_mr;
    fread(&remote_write_mr, sizeof(remote_write_mr), 1, read_pipe);
    fclose(read_pipe);

	memset(&wr_write, 0, sizeof(wr_write));
	wr_write.sg_list             = &sg_write;
	wr_write.num_sge             = 1;
	wr_write.opcode              = IBV_WR_RDMA_WRITE_WITH_IMM;
	wr_write.send_flags          = IBV_SEND_SIGNALED;
    wr_write.imm_data            = htonl(0x1234);
    wr_write.wr.rdma.remote_addr = (uintptr_t)remote_write_mr.addr;
    wr_write.wr.rdma.rkey        = remote_write_mr.rkey;

    /* For Write, it isn't necesarry to consume work completions, even though they are generated */
	ret = ibv_post_send(qp.get(), &wr_write, &bad_wr_write);
	if (ret != 0)
	{
		std::cerr << "Error: " << " (" << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << ")" << std::endl;
		return ret;
	}

    ibv_dereg_mr(read_mr);
    ibv_dereg_mr(write_mr);

	return 0;
}
