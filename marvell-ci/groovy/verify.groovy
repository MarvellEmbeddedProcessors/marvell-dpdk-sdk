/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

def run(Object s)
{
	stage ('Verification') {
		if (s.utils.get_flag(s, "nightly_regression")) {
			if (!s.utils.get_flag(s, "run_test-cn96-perf"))
				error "-E- Didn't verify all regression tests"
		} else {
			if (s.utils.get_flag(s, "skip_build"))
				error "-E- Didn't verify all mandatory builds"

			if (!s.utils.get_flag(s, "run_base") || s.utils.get_flag(s, "skip_test")) {
				s.utils.gerrit_add_comment(s, "WARN: Base Test Stages not run !!!")

				if (s.HEAD_COMMIT)
					error """
					-E- Didn't verify mandatory tests required for review's \
					top commit
					"""
			}
		}

		println "CI Flags Sanity check passed"
	}
}

return this
