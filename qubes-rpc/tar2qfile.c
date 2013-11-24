/*	$OpenBSD: tar.h,v 1.7 2003/06/02 23:32:09 millert Exp $	*/
/*	$NetBSD: tar.h,v 1.3 1995/03/21 09:07:51 cgd Exp $	*/

/*-
 * Copyright (c) 1992 Keith Muller.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Keith Muller of the University of California, San Diego.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tar.h	8.2 (Berkeley) 4/18/94
 */

#define _GNU_SOURCE /* For O_NOFOLLOW. */
#include <errno.h>
#include <ioall.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <qfile-utils.h>

/***************************************************
 * Most routines extracted from the PAX project (tar.c...) *
 ***************************************************/

/*
 * BSD PAX global data structures and constants.
 */

#define	MAXBLK		64512	/* MAX blocksize supported (posix SPEC) */
				/* WARNING: increasing MAXBLK past 32256 */
				/* will violate posix spec. */
#define	MAXBLK_POSIX	32256	/* MAX blocksize supported as per POSIX */
#define BLKMULT		512	/* blocksize must be even mult of 512 bytes */
				/* Don't even think of changing this */
#define DEVBLK		8192	/* default read blksize for devices */
#define FILEBLK		10240	/* default read blksize for files */
#define PAXPATHLEN	3072	/* maximium path length for pax. MUST be */


/*
 * defines and data structures common to all tar formats
 */
#define CHK_LEN		8		/* length of checksum field */
#define TNMSZ		100		/* size of name field */
#define NULLCNT		2		/* number of null blocks in trailer */
#define CHK_OFFSET	148		/* start of chksum field */
#define BLNKSUM		256L		/* sum of checksum field using ' ' */

/*
 * General Defines
 */
#define HEX		16
#define OCT		8
#define _PAX_		1
#define _TFILE_BASE	"paxXXXXXXXXXX"

/*
 * General Macros
 */
#ifndef MIN
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define	MAX(a,b) (((a)>(b))?(a):(b))
#endif
#define MAJOR(x)	major(x)
#define MINOR(x)	minor(x)
#define TODEV(x, y)	makedev((x), (y))


/*
 * Values used in typeflag field in all tar formats
 * (only REGTYPE, LNKTYPE and SYMTYPE are used in old bsd tar headers)
 */
#define	REGTYPE		'0'		/* Regular File */
#define	AREGTYPE	'\0'		/* Regular File */
#define	LNKTYPE		'1'		/* Link */
#define	SYMTYPE		'2'		/* Symlink */
#define	CHRTYPE		'3'		/* Character Special File */
#define	BLKTYPE		'4'		/* Block Special File */
#define	DIRTYPE		'5'		/* Directory */
#define	FIFOTYPE	'6'		/* FIFO */
#define	CONTTYPE	'7'		/* high perf file */

/*
 * GNU tar compatibility;
 */
#define	LONGLINKTYPE	'K'		/* Long Symlink */
#define	LONGNAMETYPE	'L'		/* Long File */
#define EXTHEADERTYPE	'x'		/* Extended header */

/*
 * Pad with a bit mask, much faster than doing a mod but only works on powers
 * of 2. Macro below is for block of 512 bytes.
 */
#define TAR_PAD(x)	((512 - ((x) & 511)) & 511)

/*
 * Data Interchange Format - Extended tar header format - POSIX 1003.1-1990
 */
#define TPFSZ		155
#define	TMAGIC		"ustar"		/* ustar and a null */
#define	TMAGLEN		6
#define	TVERSION	"00"		/* 00 and no null */
#define	TVERSLEN	2

typedef struct {
	char name[TNMSZ];		/* name of entry */
	char mode[8]; 			/* mode */
	char uid[8]; 			/* uid */
	char gid[8];			/* gid */
	char size[12];			/* size */
	char mtime[12];			/* modification time */
	char chksum[CHK_LEN];		/* checksum */
	char typeflag;			/* type of file. */
	char linkname[TNMSZ];		/* linked to name */
	char magic[TMAGLEN];		/* magic cookie */
	char version[TVERSLEN];		/* version */
	char uname[32];			/* ascii owner name */
	char gname[32];			/* ascii group name */
	char devmajor[8];		/* major device number */
	char devminor[8];		/* minor device number */
	char prefix[TPFSZ];		/* linked to name */
} HD_USTAR;


/*
 * Routines for manipulating headers, trailers:
 * asc_ul()
 * tar_trail()
 * tar_chksm()
 * ustar_id()
 */

static unsigned long tar_chksm (char *, int);
char *gnu_hack_string;          /* GNU ././@LongLink hackery */

char untrusted_namebuf[MAX_PATH_LENGTH];
extern int ignore_quota_error;

struct filters {
    int filters_count;
    char **filters;
    int *filters_matches;
    int matched_filters;
};


/*
 * asc_ul()
 *	convert hex/octal character string into a u_long. We do not have to
 *	check for overflow! (the headers in all supported formats are not large
 *	enough to create an overflow).
 *	NOTE: strings passed to us are NOT TERMINATED.
 * Return:
 *	unsigned long value
 */

u_long
asc_ul (char *str, int len, int base)
{
  char *stop;
  u_long tval = 0;

  stop = str + len;

  /*
   * skip over leading blanks and zeros
   */
  while ((str < stop) && ((*str == ' ') || (*str == '0')))
    ++str;

  /*
   * for each valid digit, shift running value (tval) over to next digit
   * and add next digit
   */
  if (base == HEX)
    {
      while (str < stop)
	{
	  if ((*str >= '0') && (*str <= '9'))
	    tval = (tval << 4) + (*str++ - '0');
	  else if ((*str >= 'A') && (*str <= 'F'))
	    tval = (tval << 4) + 10 + (*str++ - 'A');
	  else if ((*str >= 'a') && (*str <= 'f'))
	    tval = (tval << 4) + 10 + (*str++ - 'a');
	  else
	    break;
	}
    }
  else
    {
      while ((str < stop) && (*str >= '0') && (*str <= '7'))
	tval = (tval << 3) + (*str++ - '0');
    }
  return (tval);
}


/*
 * tar_trail()
 *	Called to determine if a header block is a valid trailer. We are passed
 *	the block, the in_sync flag (which tells us we are in resync mode;
 *	looking for a valid header), and cnt (which starts at zero) which is
 *	used to count the number of empty blocks we have seen so far.
 * Return:
 *	0 if a valid trailer, -1 if not a valid trailer, or 1 if the block
 *	could never contain a header.
 */

int
tar_trail (char *buf,
	   int in_resync, int *cnt)
{
  register int i;

  /*
   * look for all zero, trailer is two consecutive blocks of zero
   */
  for (i = 0; i < BLKMULT; ++i)
    {
      if (buf[i] != '\0')
	break;
    }

  /*
   * if not all zero it is not a trailer, but MIGHT be a header.
   */
  if (i != BLKMULT)
    return (-1);

  /*
   * When given a zero block, we must be careful!
   * If we are not in resync mode, check for the trailer. Have to watch
   * out that we do not mis-identify file data as the trailer, so we do
   * NOT try to id a trailer during resync mode. During resync mode we
   * might as well throw this block out since a valid header can NEVER be
   * a block of all 0 (we must have a valid file name).
   */
  if (!in_resync && (++*cnt >= NULLCNT))
    return (0);
  return (1);
}


/*
 * tar_chksm()
 *	calculate the checksum for a tar block counting the checksum field as
 *	all blanks (BLNKSUM is that value pre-calculated, the sum of 8 blanks).
 *	NOTE: we use len to short circuit summing 0's on write since we ALWAYS
 *	pad headers with 0.
 * Return:
 *	unsigned long checksum
 */

static unsigned long
tar_chksm (char *blk, int len)
{
  char *stop;
  char *pt;
  unsigned int chksm = BLNKSUM;	/* initial value is checksum field sum */

  /*
   * add the part of the block before the checksum field
   */
  pt = blk;
  stop = blk + CHK_OFFSET;
  while (pt < stop)
    chksm += (*pt++ & 0xff);
  /*
   * move past the checksum field and keep going, spec counts the
   * checksum field as the sum of 8 blanks (which is pre-computed as
   * BLNKSUM).
   * ASSUMED: len is greater than CHK_OFFSET. (len is where our 0 padding
   * starts, no point in summing zero's)
   */
  pt += CHK_LEN;
  stop = blk + len;
  while (pt < stop)
    chksm += (*pt++ & 0xff);

  return chksm;
}


/*
 * ustar_id()
 *	determine if a block given to us is a valid ustar header. We have to
 *	be on the lookout for those pesky blocks of all zero's
 * Return:
 *	0 if a ustar header, -1 otherwise
 */

int
ustar_id (char *blk, size_t size)
{
  HD_USTAR *hd;

  if (size < BLKMULT)
    return (-1);
  hd = (HD_USTAR *) blk;

  /*
   * check for block of zero's first, a simple and fast test then check
   * ustar magic cookie. We should use TMAGLEN, but some USTAR archive
   * programs are fouled up and create archives missing the \0. Last we
   * check the checksum. If ok we have to assume it is a valid header.
   */
  if (hd->name[0] == '\0')
    return (-1);
  if (strncmp (hd->magic, TMAGIC, TMAGLEN - 1) != 0)
    return (-1);
  if (asc_ul (hd->chksum, sizeof (hd->chksum), OCT) !=
      tar_chksm (blk, BLKMULT))
    return (-1);
  return (0);
}


/*
 * Routines for reading tar files

// Source: http://www.mkssoftware.com/docs/man4/pax.4.asp
struct file_header {	// PAX header is similar as file_header and can be completely ignored
	unsigned char[100] name;
	unsigned char[8] mode;
	unsigned char[8] uid; // unused
	unsigned char[8] gid; // unused
	unsigned char[12] size; // 0 if file is a link
	unsigned char[12] mtime;
	unsigned char[8] chksum;
	unsigned char[1] typeflag;
	unsigned char[100] linkname;
	unsigned char[6] magic; //ustar
	unsigned char[2] version; // 00
	unsigned char[32] uname; // unused
	unsigned char[32] gname; // unused
	unsigned char[8] devmajor; // unused ?
	unsigned char[8] devminor; // unused ?
	unsigned char[155] prefix;  // only used for files > 100 characters. could be unused ?
};

enum {
	TYPE_REGULAR,		//0
	TYPE_ARCHIVE_LINK,	//1
	TYPE_SYMLINK,		//2
	TYPE_CHARACTER_DEVICE,	//3
	TYPE_BLOCK_DEVICE,	//4
	TYPE_DIRECTORY,		//5
	TYPE_FIFO,		//6
	// Other types:
	TYPE_EXTENDED_USAGE,	//xxxxx
	// A-Z are available for custom usage
};

// Extended attribute:
// length keyword=value
// atime, charset, comment, gname, linkpath, mtime, path, size, uname

*/


enum {
	NEED_NOTHING,
	NEED_SKIP,
	NEED_SKIP_FILE, // distinguish between skipped file and unwanted blocks (extended headers etc)
	NEED_READ,
	NEED_SYNC_TRAIL,
	INVALID_HEADER,
	MEMORY_ALLOC_FAILED,
};


/*
 * ustar_rd()
 *	extract the values out of block already determined to be a ustar header.
 *	store the values in the ARCHD parameter.
 * Return:
 *	0
 */

int n_dirs = 0;
char ** dirs_headers_sent = NULL;

int
ustar_rd (int fd, struct file_header * untrusted_hdr, char *buf, struct stat * sb, struct filters *filters)
{

  register HD_USTAR *hd;
  register char *dest;
  register int cnt = 0;
  int ret;
  int i;
  int should_extract;
  /* DISABLED: unused
  dev_t devmajor;
  dev_t devminor;
  */

  /*
   * we only get proper sized buffers
   */
  fprintf(stderr,"Checking if valid header\n");
  if (ustar_id (buf, BLKMULT) < 0) {
    fprintf (stderr,"Invalid header\n");
    return INVALID_HEADER;
  }
  fprintf(stderr,"Valid header!\n");
  /* DISABLED: Internal to PAX
  arcn->org_name = arcn->name;
  arcn->sb.st_nlink = 1;
  arcn->pat = NULL;
  arcn->nlen = 0;
  */
  untrusted_hdr->namelen = 0;

  hd = (HD_USTAR *) buf;

  /*
   * see if the filename is split into two parts. if, so joint the parts.
   * we copy the prefix first and add a / between the prefix and name.
   */
  dest = untrusted_namebuf;
  if (*(hd->prefix) != '\0')
    {
      cnt = strlen(strncpy (dest, hd->prefix,
		     MIN(sizeof (untrusted_namebuf) - 1,TPFSZ+1)));
      dest += cnt;
      *dest++ = '/';
      cnt++;
    }
  if (gnu_hack_string)
    {
      untrusted_hdr->namelen = cnt + strlen(strncpy (dest, gnu_hack_string,
				  MIN(TNMSZ+1, sizeof (untrusted_namebuf) - cnt)));
      free(gnu_hack_string);
      gnu_hack_string = NULL;
    } else
      untrusted_hdr->namelen = cnt + strlen(strncpy (dest, hd->name,
				  MIN(TNMSZ+1, sizeof (untrusted_namebuf) - cnt)));

  // qfile count the \0 in the namelen
  untrusted_hdr->namelen += 1;

  fprintf(stderr,"Retrieved name len: %d\n",untrusted_hdr->namelen);
  fprintf(stderr,"Retrieved name: %s\n",untrusted_namebuf);

  /*
   * follow the spec to the letter. we should only have mode bits, strip
   * off all other crud we may be passed.
   */
  sb->st_mode = (mode_t) (asc_ul (hd->mode, sizeof (hd->mode), OCT) &
			       0xfff);
  untrusted_hdr->mode = sb->st_mode;

  #if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64
  sb->st_size = (off_t) asc_uqd (hd->size, sizeof (hd->size), OCT);
  #else
  sb->st_size = (off_t) asc_ul (hd->size, sizeof (hd->size), OCT);
  #endif

  untrusted_hdr->filelen = sb->st_size;
  untrusted_hdr->atime = (time_t) asc_ul (hd->mtime, sizeof (hd->mtime), OCT);
  untrusted_hdr->mtime = untrusted_hdr->atime;
  untrusted_hdr->atime_nsec = untrusted_hdr->mtime_nsec = 0;

  sb->st_mtime = (time_t) asc_ul (hd->mtime, sizeof (hd->mtime), OCT);
  sb->st_ctime = sb->st_atime = sb->st_mtime;


  /*
   * If we can find the ascii names for gname and uname in the password
   * and group files we will use the uid's and gid they bind. Otherwise
   * we use the uid and gid values stored in the header. (This is what
   * the posix spec wants).
   */
  /* DISABLED: unused
  hd->gname[sizeof (hd->gname) - 1] = '\0';
  if (gid_name (hd->gname, &(arcn->sb.st_gid)) < 0)
    arcn->sb.st_gid = (gid_t) asc_ul (hd->gid, sizeof (hd->gid), OCT);
  hd->uname[sizeof (hd->uname) - 1] = '\0';
  if (uid_name (hd->uname, &(arcn->sb.st_uid)) < 0)
    arcn->sb.st_uid = (uid_t) asc_ul (hd->uid, sizeof (hd->uid), OCT);
  */

  /*
   * set the defaults, these may be changed depending on the file type
   */
  /* Disabled: pax specific
  arcn->ln_name[0] = '\0';
  arcn->ln_nlen = 0;
  arcn->pad = 0;
  arcn->skip = 0;
  arcn->sb.st_rdev = (dev_t) 0;
  */
  

  /*
   * set the mode and PAX type according to the typeflag in the header
   */
  switch (hd->typeflag)
    {
    case FIFOTYPE:
	fprintf(stderr,"File is FIFOTYPE\n");
      /* DISABLED: unused
      arcn->type = PAX_FIF;
      arcn->sb.st_mode |= S_IFIFO;
      */
      break;
    case DIRTYPE:
	fprintf(stderr,"File is DIRTYPE\n");
      /* DISABLED: unused
      arcn->type = PAX_DIR;
      arcn->sb.st_mode |= S_IFDIR;
      arcn->sb.st_nlink = 2;
      */
      /*
       * Some programs that create ustar archives append a '/'
       * to the pathname for directories. This clearly violates
       * ustar specs, but we will silently strip it off anyway.
       */
/*
      if (arcn->name[arcn->nlen - 1] == '/')
	arcn->name[--arcn->nlen] = '\0';
*/
      break;
    case BLKTYPE:
	fprintf(stderr,"File is BLKTYPE\n");
	break;
    case CHRTYPE:
	fprintf(stderr,"File is CHRTYPE\n");
      /*
       * this type requires the rdev field to be set.
       */
      if (hd->typeflag == BLKTYPE)
	{
/*
	  arcn->type = PAX_BLK;
	  arcn->sb.st_mode |= S_IFBLK;
*/
	}
      else
	{
/*
	  arcn->type = PAX_CHR;
	  arcn->sb.st_mode |= S_IFCHR;
*/
	}
      /* DISABLED: unused
      devmajor = (dev_t) asc_ul (hd->devmajor, sizeof (hd->devmajor), OCT);
      devminor = (dev_t) asc_ul (hd->devminor, sizeof (hd->devminor), OCT);
      */
//      arcn->sb.st_rdev = TODEV (devmajor, devminor);
      break;
    case SYMTYPE:
	fprintf(stderr,"File is SYMTYPE\n");
	break;
    case LNKTYPE:
	fprintf(stderr,"File is LNKTYPE\n");
      if (hd->typeflag == SYMTYPE)
	{
//	  arcn->type = PAX_SLK;
//	  arcn->sb.st_mode |= S_IFLNK;
	}
      else
	{
//	  arcn->type = PAX_HLK;
	  /*
	   * so printing looks better
	   */
//	  arcn->sb.st_mode |= S_IFREG;
//	  arcn->sb.st_nlink = 2;
	}
      /*
       * copy the link name
       */
//      arcn->ln_nlen = strlcpy (arcn->ln_name, hd->linkname,
//			       MIN(TNMSZ+1,sizeof (arcn->ln_name)));
      break;
    case LONGLINKTYPE:
	fprintf(stderr,"File is LONGLINKTYPE\n");
	break;
    case LONGNAMETYPE:
	fprintf(stderr,"File is LONGNAMETYPE\n");
      /*
       * GNU long link/file; we tag these here and let the
       * pax internals deal with it -- too ugly otherwise.
       */
//      arcn->type =
//	hd->typeflag == LONGLINKTYPE ? PAX_GLL : PAX_GLF;
//      arcn->pad = TAR_PAD(arcn->sb.st_size);
//      arcn->skip = arcn->sb.st_size;
//      arcn->ln_name[0] = '\0';
//      arcn->ln_nlen = 0;
      break;
    case CONTTYPE:
	fprintf(stderr,"File is CONTTYPE\n");
	break;
    case AREGTYPE:
	fprintf(stderr,"File is AREGTYPE\n");
	break;
    case REGTYPE:
	fprintf(stderr,"File is REGTYPE of size %ld\n",sb->st_size);

	// Check if user want to extract this file
	should_extract = 1;
	for (i=0; i < filters->filters_count; i++) {
		should_extract = 0;
		fprintf(stderr, "Comparing with filter %s\n", filters->filters[i]);
		if (strncmp(untrusted_namebuf, filters->filters[i], strlen(filters->filters[i])) == 0) {
			fprintf(stderr, "Match (%d)\n", filters->filters_matches[i]);
			should_extract = 1;
			filters->filters_matches[i]++;
			if (filters->filters_matches[i] == 1) {
			    // first match
			    filters->matched_filters++;
			}
			break;
		}
	}
	if (should_extract != 1) {
		fprintf(stderr, "File should be filtered.. Skipping\n");
		return NEED_SKIP_FILE;
	}

        // Create a copy of untrusted_namebuf to be used for strtok
	char * dirbuf;
	dirbuf = malloc(sizeof (char) * (untrusted_hdr->namelen));
	if (dirbuf == NULL)
		return MEMORY_ALLOC_FAILED;
	dirbuf = strncpy(dirbuf, untrusted_namebuf, untrusted_hdr->namelen);

	int i = 0;
	int dir_found = 0;
	size_t pathsize = 0;
	char * path = NULL;
	struct file_header dir_header;

        // Split the path in directories and recompose it incrementally
	char * last_token = strtok(dirbuf,"/");
	char * token = strtok(NULL, "/");
	while (token != NULL) {
		
		fprintf(stderr,"Found directory %s (last:%s)\n",token,last_token);

		// Recompose the path based on last discovered directory
		if (path == NULL) {
			path = malloc(sizeof (char) * (strlen(last_token)+1));
			if (path == NULL)
				return MEMORY_ALLOC_FAILED;
			path = strncpy(path, last_token, strlen(last_token));
			path[strlen(last_token)] = '\0';
		} else {
			pathsize = strlen(path);
			path = realloc(path, sizeof (char) * (strlen(path)+1+strlen(last_token)+1));
			if (path == NULL)
				return MEMORY_ALLOC_FAILED;
			path[pathsize] = '/';
			
			strncpy(path+pathsize+1, last_token, strlen(last_token));
			path[pathsize+strlen(last_token)+1] = '\0';
		}
		fprintf(stderr,"Path is %s\n",path);

		fprintf(stderr,"Checking from i=0 i<%d\n",n_dirs);
		// Verify if qfile headers for the current path have already been sent based on the dirs_headers_sent table
		dir_found = 0;
		for (i = 0; i < n_dirs; ++i) {
			fprintf(stderr,"Comparing with %d %d %s %s\n",i,n_dirs,dirs_headers_sent[i],path);
			if (strcmp(dirs_headers_sent[i],path)==0) {
				fprintf(stderr,"Directory headers already sent\n");
				dir_found=1;
			}
		}
		if (dir_found == 0) {
                        // Register the current path as being sent in the dirs_headers_sent table
			fprintf(stderr,"Inserting %s into register\n",path);
			dirs_headers_sent = realloc(dirs_headers_sent, sizeof (char*) * n_dirs++);
			if (dirs_headers_sent == NULL)
				return MEMORY_ALLOC_FAILED;
			dirs_headers_sent[n_dirs-1] = malloc(sizeof (char) * (strlen(path)+1));
			if (dirs_headers_sent[n_dirs-1] == NULL)
				return MEMORY_ALLOC_FAILED;
			strncpy(dirs_headers_sent[n_dirs-1], path, strlen(path)+1);

                        // Initialize the qfile headers for the current directory path
			dir_header.namelen = strlen(path)+1;
			dir_header.atime = untrusted_hdr->atime;
			dir_header.atime_nsec = untrusted_hdr->atime_nsec;
			dir_header.mtime = untrusted_hdr->mtime;
			dir_header.mtime_nsec = untrusted_hdr->mtime_nsec;

			dir_header.mode = untrusted_hdr->mode | S_IFDIR;
			dir_header.filelen = 0;
		
			fprintf(stderr,"Sending directory headers for %s\n",path);
                        // Send the qfile headers for the current directory path
			write_headers(&dir_header, path);
		}
		last_token = token;
		token = strtok(NULL, "/");
	}
	free(path);
	free(dirbuf);
	
	fprintf(stderr,"End of directory checks\n");

	// Restore POSIX stat file mode (because PAX format use its own file type)
	untrusted_hdr->mode |= S_IFREG;
	fprintf(stderr,"Writing file header\n");
        // Send header and file content
	write_headers(untrusted_hdr, untrusted_namebuf);
	fprintf(stderr,"Writing file content\n");
	ret = copy_file(1, fd, untrusted_hdr->filelen, &crc32_sum);

	fprintf(stderr,"Copyfile returned with error %d\n",ret);
	if (ret != COPY_FILE_OK) {
		if (ret != COPY_FILE_WRITE_ERROR)
			gui_fatal("Copying file %s: %s", untrusted_namebuf,
				  copy_file_status_to_str(ret));
		else {
			fprintf(stderr,"UNKNOWN ERROR RETURN STATUS:%d\n.. Waiting...\n",ret);
			set_block(0);
			wait_for_result();
			exit(1);
		}
	}
	// Extract extra padding
	fprintf(stderr,"Need to remove pad:%lld %lld\n",untrusted_hdr->filelen,BLKMULT-(untrusted_hdr->filelen%BLKMULT));
	if (untrusted_hdr->filelen%BLKMULT > 0)
		ret = read(fd, buf, BLKMULT-(untrusted_hdr->filelen%BLKMULT));
	fprintf(stderr,"Removed %d bytes of padding\n",ret);

	// Resync trailing headers in order to find next file chunck in the tar file
	return NEED_SYNC_TRAIL;

	break;
    case EXTHEADERTYPE:
	fprintf(stderr,"Extended HEADER encountered\n");

	return NEED_SKIP;
	break;
    default:
	fprintf(stderr,"Default type detected:%c\n",hd->typeflag);
	return NEED_SKIP;
      /*
       * these types have file data that follows. Set the skip and
       * pad fields.
       */
//      arcn->type = PAX_REG;
//      arcn->pad = TAR_PAD (arcn->sb.st_size);
//      arcn->skip = arcn->sb.st_size;
//      arcn->sb.st_mode |= S_IFREG;
      break;
    }
  return NEED_SKIP;
}



void tar_file_processor(int fd, struct filters *filters)
{
	int ret;
	int i;
	int current;

	struct file_header hdr;
	struct stat sb;			/* stat buffer see stat(2) */

	char buf[BLKMULT+1];
	size_t size;

	i=0;
	current = NEED_READ;
	size_t to_skip = 0;
	int sync_count = 0;
	while ((size = read(fd, &buf, BLKMULT))) {
		if (size != -1) {
			fprintf(stderr,"Read %ld bytes\n",size);
			ret = 0;
			if (current==NEED_SYNC_TRAIL) {
				ret = tar_trail (buf, 1, &sync_count);
				fprintf(stderr,"Synchronizing trail: %d %d\n",ret,sync_count);
				if (ret != 1) {
					current = NEED_READ;
				}
			}
			if (current==NEED_READ) {
				current = ustar_rd(fd, &hdr, buf, &sb, filters);
				fprintf(stderr,"Return %d\n",ret);
			}
			if (current==NEED_SKIP || current==NEED_SKIP_FILE) {
				if (current==NEED_SKIP_FILE &&
					filters->filters_count > 0 &&
					filters->filters_count == filters->matched_filters) {
				    // This assume that either:
				    //  a) files are sorted (using full path as sort key)
				    //  b) all the directory content is in
				    //     consecutive block and only directories
				    //      are given as filters
				    // This is true for backups prepared by qvm-backup
#ifdef DEBUG
				    fprintf(stderr, "All filters matched at least once - assuming end of requested data\n");
#endif
				    return;
				}
#ifdef DEBUG
				fprintf(stderr,"Need to skip %lld bytes (matched filters %d < %d)\n",
					hdr.filelen, filters->matched_filters, filters->filters_count);
#endif
				to_skip = hdr.filelen;
				while (to_skip > 0) {
					to_skip -= read(fd, &buf, MIN(to_skip,BLKMULT));
				}
	
				// Extract extra padding
				fprintf(stderr,"Need to remove pad:%ld %lld %lld\n",to_skip,hdr.filelen,BLKMULT-(hdr.filelen%BLKMULT));
				if (hdr.filelen%BLKMULT > 0) {
					ret = read(fd, &buf, BLKMULT-(hdr.filelen%BLKMULT));
					fprintf(stderr,"Removed %d bytes of padding\n",ret);
				}
				current = NEED_SYNC_TRAIL;
			} 
			i++;
		}
		//if (i >= 10)
		//	exit(0);
	}

}

int main(int argc, char **argv)
{
	int i;
	char *entry;
	int fd;
	int use_stdin = 1;
	struct filters filters;

	signal(SIGPIPE, SIG_IGN);
	// this will allow checking for possible feedback packet in the middle of transfer
	// if disabled, the copy_file process could hang
	notify_progress(0, PROGRESS_FLAG_INIT);
	//set_size_limit(1500000000, 2048);

	crc32_sum = 0;
	/* when extracting backup header, dom0 will terminate the transfer with
	 * EDQUOT just after getting qubes.xml */
	ignore_quota_error = 1;
	for (i = 1; i < argc; i++) {
		set_nonblock(0);
		if (strcmp(argv[i], "--ignore-symlinks")==0) {
			ignore_symlinks = 1;
			continue;
		} else if (strcmp(argv[i], "-")==0) {
			use_stdin = 1;
			i++;
			break;
		} else {
			// Parse tar file
			use_stdin = 0;
			entry = argv[i];
			fprintf(stderr,"Parsing file %s\n",entry);

			fd = open(entry, O_RDONLY);
			if (fd < 0) {
				fprintf(stderr,"Error opening file %s\n",entry);
				exit(2);
			}
			i++;
			break;
		}
	}
	filters.filters_count = argc-i;
	filters.filters = argv+i;
	filters.filters_matches = calloc(filters.filters_count, sizeof(int));
	if (filters.filters_matches == NULL) {
	    perror("calloc");
	    exit(1);
	}
	filters.matched_filters = 0;

	if (use_stdin == 1) {
		// No argument specified. Use STDIN
		fprintf(stderr,"Using STDIN\n");
		set_block(0);
		fd = 0;
	}
	tar_file_processor(fd, &filters);


	notify_end_and_wait_for_result();
	notify_progress(0, PROGRESS_FLAG_DONE);
	return 0;
}


