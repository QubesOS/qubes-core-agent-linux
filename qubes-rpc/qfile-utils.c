
#include <qfile-utils.h>

unsigned long crc32_sum;
int ignore_symlinks = 0;
int ignore_quota_error = 0;

void notify_progress(int size, int flag)
{
	static long long total = 0;
	static long long prev_total = 0;
	total += size;
	if (total > prev_total + PROGRESS_NOTIFY_DELTA
	    || (flag != PROGRESS_FLAG_NORMAL)) {
		// check for possible error from qfile-unpacker; if error occured,
		// exit() will be called, so don't bother with current state
		// (notify_progress can be called as callback from copy_file())
		if (flag == PROGRESS_FLAG_NORMAL)
			wait_for_result();
		do_notify_progress(total, flag);
		prev_total = total;
	}
}

void do_notify_progress(long long total, int flag)
{
	char *du_size_env = getenv("FILECOPY_TOTAL_SIZE");
	char *progress_type_env = getenv("PROGRESS_TYPE");
	char *saved_stdout_env = getenv("SAVED_FD_1");
	if (!progress_type_env)
		return;
	if (!strcmp(progress_type_env, "console") && du_size_env) {
		char msg[256];
		snprintf(msg, sizeof(msg), "sent %lld/%lld KB\r",
			 total / 1024, strtoull(du_size_env, NULL, 0));
		write(2, msg, strlen(msg));
		if (flag == PROGRESS_FLAG_DONE)
			write(2, "\n", 1);
	}
	if (!strcmp(progress_type_env, "gui") && saved_stdout_env) {
		char msg[256];
		snprintf(msg, sizeof(msg), "%lld\n", total);
		write(strtoul(saved_stdout_env, NULL, 0), msg,
		      strlen(msg));
	}
}

void notify_end_and_wait_for_result()
{
	struct file_header end_hdr;

	/* nofity end of transfer */
	memset(&end_hdr, 0, sizeof(end_hdr));
	end_hdr.namelen = 0;
	end_hdr.filelen = 0;
	write_all_with_crc(1, &end_hdr, sizeof(end_hdr));

	set_block(0);
	wait_for_result();
}

int write_all_with_crc(int fd, void *buf, int size)
{
	crc32_sum = Crc32_ComputeBuf(crc32_sum, buf, size);
	return write_all(fd, buf, size);
}

void wait_for_result()
{
	struct result_header hdr;
	struct result_header_ext hdr_ext;
	char last_filename[MAX_PATH_LENGTH + 1];
	char last_filename_prefix[] = "; Last file: ";

	if (!read_all(0, &hdr, sizeof(hdr))) {
		if (errno == EAGAIN) {
			// no result sent and stdin still open
			return;
		} else {
			// other read error or EOF
			exit(1);	// hopefully remote has produced error message
		}
	}
	if (!read_all(0, &hdr_ext, sizeof(hdr_ext))) {
		// remote used old result_header struct
		hdr_ext.last_namelen = 0;
	}
	if (hdr_ext.last_namelen > MAX_PATH_LENGTH) {
		// read only at most MAX_PATH_LENGTH chars
		hdr_ext.last_namelen = MAX_PATH_LENGTH;
	}
	if (!read_all(0, last_filename, hdr_ext.last_namelen)) {
		fprintf(stderr, "Failed to get last filename\n");
		hdr_ext.last_namelen = 0;
	}
	last_filename[hdr_ext.last_namelen] = '\0';
	if (!hdr_ext.last_namelen)
		/* set prefix to empty string */
		last_filename_prefix[0] = '\0';

	errno = hdr.error_code;
	if (hdr.error_code != 0) {
		switch (hdr.error_code) {
			case EEXIST:
				gui_fatal("File copy: not overwriting existing file. Clean QubesIncoming dir, and retry copy%s%s", last_filename_prefix, last_filename);
				break;
			case EINVAL:
				gui_fatal("File copy: Corrupted data from packer%s%s", last_filename_prefix, last_filename);
				break;
			case EDQUOT:
				if (ignore_quota_error) {
					/* skip also CRC check as sender and receiver might be
					 * desynchronized in this case */
					return;
				}
				/* fall though */
			default:
				gui_fatal("File copy: %s%s%s",
						strerror(hdr.error_code), last_filename_prefix, last_filename);
		}
	}
	if (hdr.crc32 != crc32_sum) {
		gui_fatal("File transfer failed: checksum mismatch");
	}
}

void write_headers(struct file_header *hdr, char *filename)
{
	if (!write_all_with_crc(1, hdr, sizeof(*hdr))
	    || !write_all_with_crc(1, filename, hdr->namelen)) {
		set_block(0);
		wait_for_result();
		exit(1);
	}
}

int single_file_processor(char *filename, struct stat *st)
{
	struct file_header hdr;
	int fd;
	mode_t mode = st->st_mode;

	hdr.namelen = strlen(filename) + 1;
	hdr.mode = mode;
	hdr.atime = st->st_atim.tv_sec;
	hdr.atime_nsec = st->st_atim.tv_nsec;
	hdr.mtime = st->st_mtim.tv_sec;
	hdr.mtime_nsec = st->st_mtim.tv_nsec;

	if (S_ISREG(mode)) {
		int ret;
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			gui_fatal("open %s", filename);
		hdr.filelen = st->st_size;
		write_headers(&hdr, filename);
		ret = copy_file(1, fd, hdr.filelen, &crc32_sum);
		if (ret != COPY_FILE_OK) {
			if (ret != COPY_FILE_WRITE_ERROR)
				gui_fatal("Copying file %s: %s", filename,
					  copy_file_status_to_str(ret));
			else {
				set_block(0);
				wait_for_result();
				exit(1);
			}
		}
		close(fd);
	}
	if (S_ISDIR(mode)) {
		hdr.filelen = 0;
		write_headers(&hdr, filename);
	}
	if (S_ISLNK(mode) && !ignore_symlinks) {
		char name[st->st_size + 1];
		if (readlink(filename, name, sizeof(name)) != st->st_size)
			gui_fatal("readlink %s", filename);
		hdr.filelen = st->st_size + 1;
		write_headers(&hdr, filename);
		if (!write_all_with_crc(1, name, st->st_size + 1)) {
			set_block(0);
			wait_for_result();
			exit(1);
		}
	}
	// check for possible error from qfile-unpacker
	wait_for_result();
	return 0;
}




