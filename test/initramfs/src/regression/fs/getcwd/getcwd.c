// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../common/test.h"

FN_TEST(getcwd_small_buffer_returns_erange)
{
	char small[1];
	TEST_ERRNO(getcwd(small, 1), ERANGE);
}
END_TEST()

FN_TEST(umask_masks_high_bits)
{
	mode_t original = umask(0);

	TEST_RES(umask(01000), _ret == 0);
	TEST_RES(umask(original), _ret == 0);
}
END_TEST()
