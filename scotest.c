#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sco.h>

#define BUFSIZE 2048

static volatile int terminate = 0;
static void sig_term(int sig) {
	        terminate = 1;
}

static int hci_up(int dd, int dev_id)
{
	if (ioctl(dd, HCIDEVUP, dev_id) < 0) {
		if (errno != EALREADY) {
			fprintf(stderr, "Can't init hci%d: %s (%d)\n",
					dev_id, strerror(errno), errno);
			return -1;
		}
	}
	return 0;
}

static int hci_bdaddr(int dd, int dev_id, bdaddr_t *local)
{
	struct hci_dev_info di;

	memset(&di, 0, sizeof(struct hci_dev_info));

	di.dev_id = dev_id;
	if(ioctl(dd, HCIGETDEVINFO, (void *)&di) < 0) {
		fprintf(stderr, "Can't get hci%d info: %s (%d)\n",
				dev_id, strerror(errno), errno);
		return -1;
	}
	bacpy(local, &di.bdaddr);
	return 0;
}

static int hci_send_req_pair(int dd, struct hci_request *r, char *pincode, int to)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	struct hci_filter nf, of;
	socklen_t olen;
	hci_event_hdr *hdr;
	int err, try;

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0)
		return -1;

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT,  &nf);
	hci_filter_set_event(EVT_CMD_STATUS, &nf);
	hci_filter_set_event(EVT_CMD_COMPLETE, &nf);
	hci_filter_set_event(EVT_LINK_KEY_REQ, &nf);
	hci_filter_set_event(EVT_PIN_CODE_REQ, &nf);
	hci_filter_set_event(r->event, &nf);
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
		return -1;

	if (hci_send_cmd(dd, r->ogf, r->ocf, r->clen, r->cparam) < 0)
		goto failed;

	try = 10;
	while (try--) {
		evt_cmd_complete *cc;
		evt_cmd_status *cs;
		evt_remote_name_req_complete *rn;
		remote_name_req_cp *cp;
		evt_link_key_req *lkrq;
		evt_pin_code_req *pcrq;
		pin_code_reply_cp pcrp;
		int len;

		if (to) {
			struct pollfd p;
			int n;

			p.fd = dd; p.events = POLLIN;
			while ((n = poll(&p, 1, to)) < 0) {
				if (errno == EAGAIN || errno == EINTR)
					continue;
				goto failed;
			}

			if (!n) {
				errno = ETIMEDOUT;
				goto failed;
			}

			to -= 10;
			if (to < 0) to = 0;

		}

		while ((len = read(dd, buf, sizeof(buf))) < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto failed;
		}

		hdr = (void *) (buf + 1);
		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		switch (hdr->evt) {
			case EVT_LINK_KEY_REQ:
				lkrq = (void *) ptr;
				hci_send_cmd(dd, OGF_LINK_CTL, OCF_LINK_KEY_NEG_REPLY, 
						6, &((*lkrq).bdaddr));
				break;

			case EVT_PIN_CODE_REQ:
				pcrq = (void *) ptr;
				size_t len;
				len = strlen(pincode);
				memset(&pcrp, 0, sizeof(pcrp));
				bacpy(&pcrp.bdaddr, &((*pcrq).bdaddr));
				memcpy(pcrp.pin_code, pincode, len);
				pcrp.pin_len = len;
				hci_send_cmd(dd, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
						PIN_CODE_REPLY_CP_SIZE, &pcrp);
				break;

			case EVT_AUTH_COMPLETE:
				goto done;

			default:
				break;
		}
	}
	errno = ETIMEDOUT;

failed:
	err = errno;
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	errno = err;
	return -1;

done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	return 0;
}

static int hci_pair(int dd, int dev_id, bdaddr_t *dst, char *pincode)
{
	uint16_t vs, handle;
	uint8_t role = 0x01;
	unsigned int ptype;
	struct sockaddr_hci a;

	evt_auth_complete rp;
	auth_requested_cp cp;
	struct hci_request rq;

	memset(&a, 0, sizeof(a));
	a.hci_family = AF_BLUETOOTH;
	a.hci_dev = dev_id;

	if (bind(dd, (struct sockaddr *)&a, sizeof(a)) < 0) {
		fprintf(stderr, "Can't bind socket on hci%d: %s (%d)\n",
				dev_id, strerror(errno), errno);
		return -1;
	}

	hci_read_voice_setting(dd, &vs, 1000);
	vs = htobs(vs);
	fprintf(stderr, "Voice setting: 0x%04x\n", vs);
	if (vs != 0x0060) {
		fprintf(stderr, "The voice setting must be 0x0060\n");
		return -1;
	}

	ptype = HCI_DM1 | HCI_DM3 | HCI_DM5 | HCI_DH1 | HCI_DH3 | HCI_DH5;

	if (hci_create_connection(dd, dst, htobs(ptype),
				htobs(0x0000), role, &handle, 25000) < 0)
	{
		fprintf(stderr, "Can't connect socket on hci%d: %s (%d)\n",
				dev_id, strerror(errno), errno);
		return -1;
	}

	cp.handle = handle;

	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_AUTH_REQUESTED;
	rq.event  = EVT_AUTH_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = AUTH_REQUESTED_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_AUTH_COMPLETE_SIZE;	

	if (hci_send_req_pair(dd, &rq, pincode, 25000) < 0) {
		fprintf(stderr, "Can't pair on hci%d: %s (%d)\n",
				dev_id, strerror(errno), errno);
		return -1;
	}

	return 0;
}

static int rfcomm_connect(bdaddr_t *src, bdaddr_t *dst)
{
	struct sockaddr_rc laddr, raddr;
	struct rfcomm_dev_req req;
	socklen_t alen;
	char dstbd[18], devname[MAXPATHLEN];
	int sk, fd, try = 30, dev = 0;

	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		fprintf(stderr, "Can't create RFCOMM socket: %s (%d)\n",
				strerror(errno), errno);
		return -1;
	}

	memset(&laddr, 0, sizeof(laddr));
	laddr.rc_family = AF_BLUETOOTH;
	bacpy(&laddr.rc_bdaddr, src);
	laddr.rc_channel = 0;
	if (bind(sk, (struct sockaddr *) &laddr, sizeof(laddr)) < 0) {
		fprintf(stderr, "Can't bind on RFCOMM socket: %s (%d)\n",
				strerror(errno), errno);
		close(sk);
		return -1;
	}

	memset(&raddr, 0, sizeof(raddr));
	raddr.rc_family = AF_BLUETOOTH;
	bacpy(&raddr.rc_bdaddr, dst);
	raddr.rc_channel = 1;

	if (connect(sk, (struct sockaddr *) &raddr, sizeof(raddr)) < 0) {
		fprintf(stderr, "Can't connect on RFCOMM socket: %s (%d)\n",
				strerror(errno), errno);
		close(sk);
		return -1;
	}

	alen = sizeof(laddr);
	if (getsockname(sk, (struct sockaddr *) &laddr, &alen) < 0) {
		fprintf(stderr, "getsockname on RFCOMM socket: %s (%d)\n",
				strerror(errno), errno);
		close(sk);
		return -1;
	}

	snprintf(devname, MAXPATHLEN - 1, "/dev/rfcomm%d", dev);
	while ((fd = open(devname, O_RDONLY)) > 0) {
		printf("%s exist,  try next.\n", devname);
		close(fd);
		dev++;
		snprintf(devname, MAXPATHLEN - 1, "/dev/rfcomm%d", dev);
	}

	memset(&req, 0, sizeof(req));
	req.dev_id = dev;
	req.flags = (1 << RFCOMM_REUSE_DLC) | (1 << RFCOMM_RELEASE_ONHUP);

	bacpy(&req.src, src);
	bacpy(&req.dst, dst);
	req.channel = 1;

	dev = ioctl(sk, RFCOMMCREATEDEV, &req);
	if (dev < 0) {
		fprintf(stderr, "Can't create RFCOMM TTY: %s (%d)\n",
				strerror(errno), errno);
		close(sk);
		return -1;
	}

	snprintf(devname, MAXPATHLEN - 1, "/dev/rfcomm%d", dev);
	while ((fd = open(devname, O_RDONLY | O_NOCTTY)) < 0) {
		if (errno == EACCES) {
			fprintf(stderr, "Can't open RFCOMM TTY %s: %s (%d)\n",
					devname, strerror(errno), errno);
			goto release;
		}
		if ((fd = open(devname, O_RDONLY | O_NOCTTY)) < 0) {
			if (try--) {
				sleep(1);
				continue;
			}
			fprintf(stderr, "Can't open RFCOMM TTY %s: %s (%d)\n",
					devname, strerror(errno), errno);
			goto release;
		}
	}

	close(sk);
	ba2str(dst, dstbd);
	printf("Connected %s to %s on channel 1\n", devname, dstbd);

	return fd;

release:
	memset(&req, 0, sizeof(req));
	req.dev_id = dev;
	req.flags = (1 << RFCOMM_HANGUP_NOW);
	ioctl(sk, RFCOMMRELEASEDEV, &req);
	close(sk);

	return -1;
}

static int sco_connect(bdaddr_t *src, bdaddr_t *dst,
		uint16_t *handle, uint16_t *mtu)
{
	struct sockaddr_sco addr;
	struct sco_conninfo conn;
	struct sco_options opts;
	socklen_t size;
	int s;

	if (( s = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO)) < 0) {
		fprintf(stderr, "Can't create SCO socket %s (%d)\n",
				strerror(errno), errno);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, src);

	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Can't bind on SCO socket %s (%d)\n",
				strerror(errno), errno);
		close(s);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, dst);

	if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Can't connect on SCO socket %s (%d)\n",
				strerror(errno), errno);
		close(s);
		return -1;
	}

	memset(&conn, 0, sizeof(conn));
	size = sizeof(conn);

	if (getsockopt(s, SOL_SCO, SCO_CONNINFO, &conn, &size) < 0) {
		fprintf(stderr, "getsockopt CONNINFO SCO socket %s (%d)\n",
				strerror(errno), errno);
		close(s);
		return -1;
	}

	memset(&opts, 0, sizeof(opts));
	size = sizeof(opts);

	if (getsockopt(s, SOL_SCO, SCO_OPTIONS, &opts, &size) < 0) {
		fprintf(stderr, "getsockopt OPTIONS SCO socket %s (%d)\n",
				strerror(errno), errno);
		close(s);
		return -1;
	}

	if (handle)
		*handle = conn.hci_handle;

	if (mtu)
		*mtu = opts.mtu;

	return s;
}

static void usage(void) {
	printf("Usage:\n"
			"\tscotest <hciX> <pincode> <bdaddr> <file>\n");
}

int main(int argc, char *argv[])
{
	struct sigaction sa;

	fd_set rfds;
	struct timeval timeout;
	unsigned char buf[2048], *p;
	int maxfd, rlen, wlen;

	int dev_id, dd, fd, rd, sd;
	uint16_t sco_handle, sco_mtu;
	bdaddr_t src, dst;

	char *filename, pincode[5];

	if (argc != 5) {
		usage();
		exit(1);
	}

	if (!strncmp(argv[1], "hci", 3)) {
		dev_id = atoi(argv[1]+3);
	} else {
		usage();
		exit(1);
	}

	memset(pincode, 0, sizeof(pincode));
	strncpy(pincode, argv[2], 4);
	printf("pincode: %s\n", pincode);

	str2ba(argv[3], &dst);
	filename = strdup(argv[4]);

	if (strcmp(filename, "-") == 0) {
		fd = 0;
	} else {
		if ((fd = open(filename, O_RDONLY)) < 0) {
			fprintf(stderr, "Can't open %s:%s (%d)\n",
					filename, strerror(errno), errno);
			exit(1);
		}
	}

	dd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (dd < 0) {
		fprintf(stderr, "Can't create HCI socket %s (%d)\n",
				strerror(errno), errno);
		exit(1);
	}

	if (hci_up(dd, dev_id) < 0) {
		close(dd);
		exit(1);
	}
	if (hci_bdaddr(dd, dev_id, &src) < 0) {
		close(dd);
		exit(1);
	}
	if (hci_pair(dd, dev_id, &dst, pincode) < 0) { 
		close(dd);
		exit(1);
	}
	close(dd);

        memset(&sa, 0, sizeof(sa));
        sa.sa_flags = SA_NOCLDSTOP;
        sa.sa_handler = sig_term;
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT,  &sa, NULL);

        sa.sa_handler = SIG_IGN;
        sigaction(SIGCHLD, &sa, NULL);
        sigaction(SIGPIPE, &sa, NULL);

	if ((rd = rfcomm_connect(&src, &dst)) < 0) {
		exit(1);
	}

	if ((sd = sco_connect(&src, &dst, &sco_handle, &sco_mtu)) < 0) {
		close(rd);
		exit(1);
	}
	fprintf(stderr, "SCO audio channel connected (handle %d, mtu %d)\n",
			sco_handle, sco_mtu);

	maxfd = (rd > sd) ? rd : sd;
	while (!terminate) {

		FD_ZERO(&rfds);
		FD_SET(rd, &rfds);
		FD_SET(sd, &rfds);

		timeout.tv_sec = 0;
		timeout.tv_usec = 10000;

		if (select(maxfd + 1, &rfds, NULL, NULL, &timeout) > 0) {

			if (FD_ISSET(rd, &rfds)) {
				memset(buf, 0, sizeof(buf));
				rlen = read(rd, buf, sizeof(buf));
				if (rlen > 0) {
					printf("%s\n", buf);
					wlen = write(rd, "OK\r\n", 4);
				}
			}

			if (FD_ISSET(sd, &rfds)) {
				memset(buf, 0, sizeof(buf));
				rlen = read(sd, buf, sizeof(buf));
				if (rlen > 0) {
					rlen = read(fd, buf, rlen);
					if (rlen <= 0) {
						printf("send sco data end.\n");
						break;
					}

					wlen = 0;
					p = buf;
					while (rlen > sco_mtu) {
						wlen += write(sd, p, sco_mtu);
						rlen -= sco_mtu;
						p += sco_mtu;
					}
					wlen += write(sd, p, rlen);
				} else {
					printf("read nothing from sco\n");
				}
			}
		}
	}

	close(rd);
	close(sd);
	return 0;
}
