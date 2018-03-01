#define _GNU_SOURCE
#define  PAM_SM_SESSION

#include <errno.h>                 // for errno, EINTR
#include <fcntl.h>                 // for open, O_RDONLY, O_DIRECTORY, O_CREAT
#include <grp.h>                   // for getgrgid, group
#include <limits.h>                // for PATH_MAX
#include <pwd.h>                   // for passwd, getpwnam
#include <sched.h>                 // for unshare, CLONE_NEWNET, CLONE_NEWNS
#include <security/_pam_types.h>   // for PAM_SUCCESS, pam_handle_t, PAM_SES...
#include <security/pam_ext.h>      // for pam_syslog
#include <security/pam_modules.h>  // for pam_get_user, PAM_EXTERN
#include <stdarg.h>                // for va_list
#include <stdio.h>                 // for NULL, fclose, fopen, fprintf, FILE
#include <stdlib.h>                // for exit, realpath
#include <string.h>                // for strerror
#include <sys/mount.h>             // for mount, MS_NOEXEC, MS_BIND, MS_NOATIME
#include <sys/stat.h>              // for mkdir
#include <sys/wait.h>              // for wait
#include <syslog.h>                // for syslog, LOG_AUTH, LOG_DEBUG
#include <unistd.h>                // for close, fchdir, fork, ssize_t

extern int pivot_root(const char * new_root, const char * put_old);

#define _pam_err(...)                                                          \
	do {                                                                       \
		if (!(flags & PAM_SILENT))                                             \
			pam_syslog(pamh, LOG_ERR, __VA_ARGS__);                            \
                                                                               \
		goto pam_done;                                                         \
	} while (0)

int cp(const char *from, const char *to)
{
	int fd_to, fd_from;
	char buf[4096];
	ssize_t nread;
	int saved_errno;

	fd_from = open(from, O_RDONLY);
	if (fd_from < 0)
		return -1;

	fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd_to < 0)
		goto out_error;

	while (nread = read(fd_from, buf, sizeof buf), nread > 0) {
		char *out_ptr = buf;
		ssize_t nwritten;

		do {
			nwritten = write(fd_to, out_ptr, nread);

			if (nwritten >= 0) {
				nread -= nwritten;
				out_ptr += nwritten;
			} else if (errno != EINTR) {
				goto out_error;
			}
		} while (nread > 0);
	}

	if (nread == 0) {
		if (close(fd_to) < 0) {
			fd_to = -1;
			goto out_error;
		}
		close(fd_from);

		/* Success! */
		return 0;
	}

out_error:
	saved_errno = errno;

	close(fd_from);
	if (fd_to >= 0)
		close(fd_to);

	errno = saved_errno;
	return -1;
}

/*
	{
	  "home": "127.0.0.1/home/bfa1a880-0e9a-447c-94b3-cdbb39fbfde8"
	}
*/

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
                                   __attribute__((unused)) int flags,
                                   int argc,
                                   const char **argv)
{
	const char *username;
	const char *arg;
	char *config = NULL, *root = NULL;
	struct passwd *pw;
	struct group *gr;
	FILE *f;
	pid_t pid;
	int i, len;
	int status = PAM_SESSION_ERR;
	int oldroot = -1, newroot = -1;

	if (argc < 2)
		_pam_err("not enough arguments (see man pam_newns)");

	for (i=0;i<2 && (arg = argv[i]) && (len = strlen(arg));i++) {
		if (config == NULL && len > 9 && !strncmp(arg, "config=/", 8))
			config = strdup(arg + 8);
		else if (root == NULL && len > 5 && !strncmp(arg, "root=/", 6))
			root = strdup(arg + 5);
		else
			_pam_err("invalid argument or duplicate key: %s", arg);
	}

	if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS)
		_pam_err("could not get username");

	if ((pw = getpwnam(username)) == NULL)
		_pam_err("getpwnam returned NULL");

	if ((gr = getgrgid(pw->pw_gid)) == NULL)
		_pam_err("getgrgid returned NULL");

	/*
		TODO: read config file here
	*/

	if (unshare(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC))
		_pam_err("unshare: %s", strerror(errno));

	/*
		fork off a new process to land in a new PID namespace
	*/
	if ((pid = fork()) == -1)
		_pam_err("fork(): %s", strerror(errno));
	else if (pid) {
		wait(NULL);
		exit(0);
	}

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		_pam_err("remounting /: %s", strerror(errno));

	/* bind mount newroot into /mnt */
	if (mount(root, "/mnt", NULL, MS_BIND | MS_RDONLY, NULL))
		_pam_err("bind mount newroot: %s", strerror(errno));

	/* and remount to ensure readonly */
	if (mount("none", "/mnt", NULL,  MS_BIND | MS_RDONLY | MS_REMOUNT, NULL))
		_pam_err("remount newroot r/o: %s", strerror(errno));

	if (sethostname(username, strlen(username)))
		_pam_err("sethostname: %s", strerror(errno));

	if ((oldroot = open("/", O_DIRECTORY | O_RDONLY)) == -1)
		_pam_err("open oldroot: %s", strerror(errno));

	if ((newroot = open("/mnt", O_DIRECTORY | O_RDONLY)) == -1)
		_pam_err("open newroot: %s", strerror(errno));

	/* change into new root */
	if (fchdir(newroot))
		_pam_err("chdir newroot: %s", strerror(errno));

	if (pivot_root(".", "mnt"))
		_pam_err("pivot_root: %s", strerror(errno));

	/* tmpfs mount to place instantiated files */
	if (mount("tmpfs", "/mnt/tmp", "tmpfs", MS_NOEXEC | MS_NOATIME, "size=64k"))
		_pam_err("mount tmpfs: %s", strerror(errno));

	/*
		/etc/passwd
	*/

	if (cp("/etc/passwd", "/mnt/tmp/passwd"))
		_pam_err("cp /etc/passwd: %s", strerror(errno));

	if (!(f = fopen("/mnt/tmp/passwd", "a")))
		_pam_err("open /etc/passwd: %s", strerror(errno));

	if (fprintf(f, "%s:x:%d:%d:%s:%s:%s\n", pw->pw_name, pw->pw_uid,
	        pw->pw_gid, pw->pw_gecos, pw->pw_dir, pw->pw_shell) < 0)
		_pam_err("write to /etc/passwd: %s", strerror(errno));

	if (fclose(f))
		_pam_err("write to /etc/passwd: %s", strerror(errno));

	if (mount("/mnt/tmp/passwd", "/etc/passwd", NULL, MS_BIND | MS_RDONLY, NULL))
		_pam_err("bind mount /etc/passwd: %s", strerror(errno));

	/*
		/etc/group
	*/

	if (cp("/etc/group", "/mnt/tmp/group"))
		_pam_err("cp /etc/group: %s", strerror(errno));

	if (!(f = fopen("/mnt/tmp/group", "a")))
		_pam_err("open /etc/group: %s", strerror(errno));

	if (fprintf(f, "%s:x:%d:\n", gr->gr_name, gr->gr_gid) < 0)
		_pam_err("write to /etc/group: %s", strerror(errno));

	if (fclose(f))
		_pam_err("write to /etc/group: %s", strerror(errno));

	if (mount("/mnt/tmp/group", "/etc/group", NULL, MS_BIND | MS_RDONLY, NULL))
		_pam_err("bind mount /etc/group: %s", strerror(errno));

	/* mount devpts */
	if (mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC,
	         "newinstance,ptmxmode=0666,mode=0620"))
		_pam_err("mount devpts: %s", strerror(errno));

	/* recursively umount/detach oldroot */
	if (umount2("/mnt", MNT_DETACH))
		_pam_err("umount oldroot: %s", strerror(errno));

	/* tmpfs to create home directory mountpoint */
	if (mount("tmpfs", "/home", "tmpfs", MS_NOEXEC | MS_NOATIME, "size=0,nr_inodes=2,mode=0755"))
		_pam_err("mount tmpfs: %s", strerror(errno));

	/* create homedir */
	if (mkdir(pw->pw_dir, 0750))
		_pam_err("mkdir homedir: %s", strerror(errno));

	/* and mount the remote nfs share over it */
	if (mount("127.0.0.1:/home/foo", pw->pw_dir, "nfs", 0, "vers=4,addr=127.0.0.1"))
		_pam_err("mount homedir: %s", strerror(errno));

	if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, "hidepid=2"))
		_pam_err("mount /proc: %s", strerror(errno));

	/* nfs is mounted, so we can unshare the network namespace */
	unshare(CLONE_NEWNET);

	/*
		TODO: send netlink messages to set loopback interface up,
		      and configure tap/veth interface
	*/

	status = PAM_SUCCESS;

pam_done:
	free(config);
	free(root);

	if (oldroot)
		close(oldroot);

	if (newroot)
		close(newroot);

	return status;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
                                   __attribute__((unused)) int flags,
                                   __attribute__((unused)) int argc,
                                   __attribute__((unused)) const char **argv)
{
	const char *username;

	if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS)
		_pam_err("could not get username");

pam_done:
	return PAM_SUCCESS;
}
