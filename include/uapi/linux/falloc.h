#ifndef _UAPI_FALLOC_H_
#define _UAPI_FALLOC_H_

#define FALLOC_FL_KEEP_SIZE	0x01 /* default is extend size */
#define FALLOC_FL_PUNCH_HOLE	0x02 /* de-allocates range */
#define FALLOC_FL_NO_HIDE_STALE	0x04 /* reserved codepoint */

/*
 * FALLOC_FL_COLLAPSE_RANGE is used to remove a range of a file
 * without leaving a hole in the file. The contents of the file beyond
 * the range being removed is appended to the start offset of the range
 * being removed (i.e. the hole that was punched is "collapsed"),
 * resulting in a file layout that looks like the range that was
 * removed never existed. As such collapsing a range of a file changes
 * the size of the file, reducing it by the same length of the range
 * that has been removed by the operation.
 *
 * Different filesystems may implement different limitations on the
 * granularity of the operation. Most will limit operations to
 * filesystem block size boundaries, but this boundary may be larger or
 * smaller depending on the filesystem and/or the configuration of the
 * filesystem or file.
 *
 * Attempting to collapse a range that crosses the end of the file is
 * considered an illegal operation - just use ftruncate(2) if you need
 * to collapse a range that crosses EOF.
 */
#define FALLOC_FL_COLLAPSE_RANGE	0x08

/*
 * FALLOC_FL_ZERO_RANGE is used to convert a range of file to zeros preferably
 * without issuing data IO. Blocks should be preallocated for the regions that
 * span holes in the file, and the entire range is preferable converted to
 * unwritten extents - even though file system may choose to zero out the
 * extent or do whatever which will result in reading zeros from the range
 * while the range remains allocated for the file.
 *
 * This can be also used to preallocate blocks past EOF in the same way as
 * with fallocate. Flag FALLOC_FL_KEEP_SIZE should cause the inode
 * size to remain the same.
 */
#define FALLOC_FL_ZERO_RANGE		0x10

#endif /* _UAPI_FALLOC_H_ */
