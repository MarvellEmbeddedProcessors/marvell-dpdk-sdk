/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

def init_env_vars(Object s) {
	def regular_branches = [
		/* ASIM binaries and images are picked up based on the ref branch name */

		/* BRANCH NAME       REF BRANCH          Enable CN10k*/
		["dpdk-21.11-devel", "dpdk-21.05-devel", true],
		["dpdk-21.08-devel", "dpdk-21.05-devel", true],
		["dpdk-21.05-devel", "dpdk-21.05-devel", true],
		["dpdk-20.11-devel", "dpdk-21.05-devel", false]
	]

	s.REF_BRANCH = "dpdk-21.05-devel"
	s.REGULAR_BRANCH = false
	s.ENABLE_CN10K = true
	for (b in regular_branches) {
		if (b[0] == env.GERRIT_BRANCH) {
			s.REGULAR_BRANCH = true
			s.REF_BRANCH = b[1]
			s.ENABLE_CN10K = b[2]
			break
		}
	}

	s.COMMIT_MESSAGE = new String(env.GERRIT_CHANGE_COMMIT_MESSAGE.decodeBase64())
	currentBuild.description = s.COMMIT_MESSAGE.readLines()[0]

	s.NFS_MOUNT = '/data/isoc_platform_devops/dev-ci/'
	s.HOST_MOUNT = '/local_data/isoc_platform_devops/dev-ci/'

	/* Directory for caching the source tar balls of dependencies */
	s.DEPS_SRC_CACHE_DIR = "${s.NFS_MOUNT}/deps_cache"

	/* Directory for storing scripts that can't be put in git */
	s.SCRIPTS_CACHE_DIR = "${s.NFS_MOUNT}/scripts_cache"
	s.NETRC_FILE = "${s.SCRIPTS_CACHE_DIR}/.netrc"

	s.DEPS_DIR = "/tmp/deps"

	s.TOOLCHAIN_NAME="gcc-10-marvell-1013.0"
	s.TOOLCHAIN_TARBALL="${s.NFS_MOUNT}/toolchain_cache/gcc-10-marvell-1013.0/marvell-tools-1013.0.tar.bz2"
	s.TOOLCHAIN_DIR="${s.HOST_MOUNT}/prebuilt/toolchain/gcc-10-marvell-1013.0"

	s.HEAD_COMMIT = s.utils.gerrit_is_head_commit(s)
	s.FAILING_FAST = false

	s.base_tests = [
		'test-cn96',
		'test-cn9k',
		'test-cn10k',
	]

	s.flags = [
		'run_all' : [ 'Run all tests', false ],
		'run_base' : [ 'Run base tests', s.HEAD_COMMIT ],
		'skip_all' : [ 'Skips all CI stages and abort the build', false],
		'skip_build' : [ 'Skips all build stages.', false ],
		'skip_checkpatch' : [ 'Skip checkpatch validation', false ],
		'skip_checkformat' : [ 'Skip check format validation', false ],
		'skip_klocwork' : [ 'Skip klocwork validation', false ],
		'skip_add_reviewers' : [ 'Skip auto addition of reviewers', false ],
		'skip_test' : [ 'Skips all tests', false],
		'run_test-cn9k' : [ 'Run CN9k tests', false],
		'run_test-cn9k-debug' : [ 'Run CN9k Debug tests', false],
		'run_test-cn96' : [ 'Run CN96 Specific tests', false],
		'run_test-cn96-perf' : [ 'Run CN96 Perf tests', false],
		'run_test-cn98-perf' : [ 'Run CN98 Perf tests', false],
		'run_test-cn10k' : [ 'Run CN10k tests', false],
		'run_test-cn10k-debug' : [ 'Run CN10k Debug tests', false],
		'run_test-cn106-perf' : [ 'Run CN106 Perf tests', false],
		'run_test-asim-cn10ka' : [ 'Run CN10ka tests', false],
		'run_test-asim-cn10ka-debug' : [ 'Run CN10ka Debug tests', false],
		'disable_failfast' : [ 'Disable failFast for parallel stages', false ],
		'skip_roc_check' : [ 'Skip ROC Files check', false ],
		'skip_check_sanity' : [ 'Skip sanity check', false ],
		'force_start' : [ 'Force start CI on non-regular branches', false ],
		'nightly_test-cn96-perf' : [ 'Enables Nightly CN96 Perf tests, checks and messages. This flag will reset other flags.', false ],
		'nightly_test-cn106-perf' : [ 'Enables Nightly CN106 Perf tests, checks and messages. This flag will reset other flags.', false ],
		'nightly_test-asim-cn10ka' : [ 'Enables Nightly CN10ka ASIM test, checks and messages. This flag will reset other flags.', false ],
		'help' : [ 'Display this help message and abort the build', false ],
	]

	print "DEPS_DIR           : ${s.DEPS_DIR}\n" +
	      "DEPS_SRC_CACHE_DIR : ${s.DEPS_SRC_CACHE_DIR}\n" +
	      "SCRIPTS_CACHE_DIR  : ${s.SCRIPTS_CACHE_DIR}\n" +
	      "TOOLCHAIN_DIR      : ${s.TOOLCHAIN_DIR}\n" +
	      "PROJECT_ROOT       : ${s.PROJECT_ROOT}\n" +
	      "BUILD_BACKUP_ROOT  : ${s.BUILD_BACKUP_ROOT}" +
	      "REGULAR BRANCH     : ${s.REGULAR_BRANCH}\n" +
	      "REF BRANCH         : ${s.REF_BRANCH}\n"
}

def init_flags(Object s) {
	def line_nmb = 0
	def override_commit = false
	def nightly_name

	if (env.GERRIT_EVENT_COMMENT_TEXT) {
		def run_flags_given = false
		def run_base_flag_given = false

		print "Parsing Gerrit Comment: \n${env.GERRIT_EVENT_COMMENT_TEXT}"
		for (w in env.GERRIT_EVENT_COMMENT_TEXT.split()) {
			if (s.utils.set_flag(s, w, true)) {
				/* If gerrit comment has asked to set ANY valid flag, then ignore commit
				 * message completely */
				override_commit = true

				if (w == "run_base") {
					run_base_flag_given = true
				} else if (w.matches("run_.*")) {
					run_flags_given = true
				}
			}
		}
		/* If user has given some run flags and not run_base, set run_base to false */
		if (run_flags_given && !run_base_flag_given)
			s.utils.set_flag(s, "run_base", false)
	}

	if (override_commit) {
		print "Commit message CI directives are overridden by Gerrit comment CI directives"
	} else {
		def lines = s.COMMIT_MESSAGE.readLines()
		def run_flags_given = false
		def run_base_flag_given = false

		print "Parsing Commit Message: \n${s.COMMIT_MESSAGE}"
		for (l in lines) {
			line_nmb++
			def tokens = l.split()
			/* Skip commit subject, empty lines and non-ci lines*/
			if (line_nmb == 1 || tokens.length == 0 || tokens[0] != "ci:")
				continue
			for (w in tokens) {
				if (s.utils.set_flag(s, w, true)) {
					if (w == "run_base") {
						run_base_flag_given = true
					} else if (w.matches("run_.*")) {
						run_flags_given = true
					}
				}
			}
		}
		/* If user has given some run flags and not run_base, set run_base to false */
		if (run_flags_given && !run_base_flag_given)
			s.utils.set_flag(s, "run_base", false)
	}

	/* Do some per-flag logic now */
	nightly_name = s.utils.get_nightly_name(s)
	if (nightly_name) {
		/* Nightly flags will reset other flags */
		for (v in s.flags)
			if (v.getKey().matches("run_.*"))
				v.getValue()[1] = false

		s.utils.set_flag(s, "skip_build", true)
		s.utils.set_flag(s, "skip_checkpatch", true)
		s.utils.set_flag(s, "skip_checkformat", true)
		s.utils.set_flag(s, "skip_klocwork", true)
		s.utils.set_flag(s, "disable_failfast", true)
		s.utils.set_flag(s, "skip_add_reviewers", true)
		s.utils.set_flag(s, "skip_roc_check", true)
		s.utils.set_flag(s, "run_test-$nightly_name", true)
	} else if (s.utils.get_flag(s, "run_all")) {
		for (v in s.flags)
			if (v.getKey().matches("run_.*"))
				v.getValue()[1] = true
	} else if (s.utils.get_flag(s, "run_base")) {
		/* If run_base is set then set the tests in base_tests */
		for (b in s.base_tests)
			s.utils.set_flag(s, "run_${b}", true)
	} else {
		/* Check whether all base tests are set. If set, set runbase also */
		def run_base = true
		for (b in s.base_tests) {
			if (!s.utils.get_flag(s, "run_${b}"))
				run_base = false
		}
		s.utils.set_flag(s, "run_base", run_base)
	}

	/* Print final flags */
	def msg = "Flags for this run:\n"
	for (v in s.flags)
		msg += "  ${v.getKey()}: ${v.getValue()[1]}\n"
	println msg
}

def check_flags(Object s) {
	if (s.utils.get_flag(s, "skip_all")) {
		stage ('Skip All') {
			error "Aborting build as skip_all flag given !!!"
		}
	}

	if (s.utils.get_flag(s, "help")) {
		stage ('Help') {
			def msg = "Following flags are available to modify CI behavior\n"
			for (v in s.flags) {
				msg += "${v.getKey()} : ${v.getValue()[0]}\n"
			}
			print msg
			error "Abort !!!"
		}
	}

	if (!s.REGULAR_BRANCH) {
		if (!s.utils.get_flag(s, "force_start")) {
			stage ('Force Stop') {
				error "Aborting as the branch is not a regular one !!!"
			}
		}
	}
}

def run(Object s) {
	stage ('Init') {
		s.utils.print_env(s)
		init_env_vars(s)
		init_flags(s)
	}
	check_flags(s)
}

return this
