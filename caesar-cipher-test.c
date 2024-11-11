#include <linux/if_alg.h>
#include <linux/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

int encrypt_test(char *to_encrypt, int len, int key) {
	int opfd;
	int tfmfd;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "caesar-cipher"
	};
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(4)] = {0};
	char buf[16];

	struct iovec iov;
	int i;

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);

  	bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
	setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY,
			&key,
			1);

	opfd = accept(tfmfd, NULL, 0);

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

	iov.iov_base = to_encrypt;
	iov.iov_len = len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sendmsg(opfd, &msg, 0);
	read(opfd, buf, len);

	for (i = 0; i < len; i++) {
		printf("%c", (unsigned char)buf[i]);
	}
	printf("\n");

	close(opfd);
	close(tfmfd);
	return 0;
}

int decrypt_test(char *to_decrypt, int len, int key) {
	int opfd;
	int tfmfd;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "caesar-cipher"
	};
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(4)] = {0};
	char buf[16];

	struct iovec iov;
	int i;

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);

  	bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
	setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY,
			&key,
			1);

	opfd = accept(tfmfd, NULL, 0);

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = ALG_OP_DECRYPT;

	iov.iov_base = to_decrypt;
	iov.iov_len = len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sendmsg(opfd, &msg, 0);
	read(opfd, buf, len);

	for (i = 0; i < len; i++) {
		printf("%c", (unsigned char)buf[i]);
	}
	printf("\n");

	close(opfd);
	close(tfmfd);
	return 0;
}

int main(int argc, char **argv) {
	encrypt_test("Hello World", 11, 2);
	decrypt_test("Vlqjoh eorfn pvj", 16, 3);
	return 0;
}
