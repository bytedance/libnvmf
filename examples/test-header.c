/*
 * Copyright 2020-2021 zhenwei pi
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */
#include <stdio.h>
#include "list.h"
#include "types.h"
#include "nvme.h"
#include "nvme-tcp.h"
#include "nvmf.h"
#include "nvmf-private.h"

int main(int argc, char *argv[])
{
	printf("sizeof struct nvme_tcp_cmd_pdu: %ld\n", sizeof(struct nvme_tcp_cmd_pdu));
	printf("sizeof struct nvme_tcp_hdr: %ld\n", sizeof(struct nvme_tcp_hdr));
	printf("sizeof struct nvme_command: %ld\n", sizeof(struct nvme_command));

	printf("sizeof struct nvme_tcp_pdu: %ld\n", sizeof(union nvme_tcp_pdu));
	printf("sizeof struct nvme_tcp_icreq_pdu: %ld\n", sizeof(struct nvme_tcp_icreq_pdu));
	printf("sizeof struct nvme_tcp_icresp_pdu: %ld\n", sizeof(struct nvme_tcp_icresp_pdu));
	printf("sizeof struct nvme_tcp_cmd_pdu: %ld\n", sizeof(struct nvme_tcp_cmd_pdu));
	printf("sizeof struct nvme_tcp_rsp_pdu: %ld\n", sizeof(struct nvme_tcp_rsp_pdu));
	printf("sizeof struct nvme_tcp_r2t_pdu: %ld\n", sizeof(struct nvme_tcp_r2t_pdu));
	printf("sizeof struct nvme_tcp_data_pdu: %ld\n", sizeof(struct nvme_tcp_data_pdu));

	printf("sizeof struct nvmf_connect_data: %ld\n", sizeof(struct nvmf_connect_data));
	printf("sizeof struct nvme_id_ctrl: %ld\n", sizeof(struct nvme_id_ctrl));

	return 0;
}
