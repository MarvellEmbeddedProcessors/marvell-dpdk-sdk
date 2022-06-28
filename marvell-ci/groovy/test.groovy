/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

def lock_board_and_test(s, board_rsrc, test_name, test_def) {
	stage ("Test: ${test_name}") {
		lock(label: "${board_rsrc}", variable: "board_ip", quantity:'1') {
			def board_ip = "${env.board_ip.trim()}"
			println "Locked ${board_rsrc} HW IP is ${board_ip}"
			s.utils.setup_board(s, board_ip, "--force-reboot")
			test_def(board_ip, "")
		}
	}
}

def lock_dual_board_and_test(s, board_rsrc, test_name, test_def) {
	stage ("Test: ${test_name}") {
		lock(label: "${board_rsrc}", variable: "perf_setup", quantity:'1') {
			def tokens = env.perf_setup.trim().split()
			def setup = tokens[0]
			def board_ip = tokens[1]
			def gen_board_ip = tokens[2]

			lock(resource: "${board_ip}") {
				s.utils.setup_board(s, board_ip, "--force-reboot")
				lock(resource: "${gen_board_ip}") {
					s.utils.setup_board(s, gen_board_ip, "--force-reboot")
					println "Locked ${setup} [${board_ip}, ${gen_board_ip}]"
					test_def(board_ip, gen_board_ip)
				}
			}
		}
	}
}

def prepare_test_stage(Object s, tests, test_name, test_env, build_name, board_rsrc) {
	if (!s.utils.get_flag(s, "run_${test_name}"))
		return

	def stg = {
		def bkp_src_dir = "${s.BUILD_BACKUP_ROOT}/src/${build_name}"
		def bkp_build_dir = "${s.BUILD_BACKUP_ROOT}/build/${build_name}"
		def build_dir = "${s.BUILD_DIR}/build/${build_name}"
		def src_dir = "${s.BUILD_DIR}/src/${build_name}"
		def run_dir = "${WORKSPACE}/${test_name}"

		def test_def = { board_ip, gen_board_ip ->
			def gen_board = ""
			def target_board = "ci@${board_ip}"

			if (gen_board_ip != "")
				gen_board = "ci@${gen_board_ip}"

			try {
				lock ("SYNC_LOCK") {
					sh script : """#!/bin/bash -x
					set -euo pipefail
					sudo mkdir -p ${s.BUILD_DIR}
					sudo chown -R jenkins:jenkins ${s.BUILD_DIR}
					mkdir -p ${src_dir}/
					mkdir -p ${build_dir}/
					rsync -a ${bkp_src_dir}/ ${src_dir}/
					rsync -a ${bkp_build_dir}/ ${build_dir}/

					cd ${src_dir}/
					export TARGET_BOARD=${target_board}
					export GENERATOR_BOARD=${gen_board}
					./marvell-ci/test/test.sh \
						-t ${src_dir}/marvell-ci/test/env/${test_env} \
						-r ${build_dir} \
						-d ${run_dir} \
						-p ${src_dir} \
						--list-only
					"""
				}
				sh (
					script: """#!/bin/bash -x
					set -euo pipefail
					cd ${src_dir}/
					export TARGET_BOARD=${target_board}
					export GENERATOR_BOARD=${gen_board}
					timeout --foreground -v -s 3 -k 30 90m \
						./marvell-ci/test/test.sh \
						-t ${src_dir}/marvell-ci/test/env/${test_env} \
						-r ${build_dir} \
						-d ${run_dir} \
						-p ${src_dir} \
						--run-only
					""",
					label: "Test ${test_name}"
				)
				s.utils.post_artifacts(test_name)
				s.TEST_STAGES_PASSED.push(test_name)
			} catch (err) {
				if (s.FAILING_FAST) {
					unstable ("Aborting as a parallel stage failed")
				} else {
					s.TEST_STAGES_FAILED.push(test_name)
					if (!s.utils.get_flag(s, "disable_failfast"))
						s.FAILING_FAST = true
					s.utils.post_artifacts(test_name)
					error "-E- Test ${test_name} failed, Exception err: ${err}"
				}
			}
		}

		if ("${board_rsrc}" == "DEV_CI_DATAPLANE_96xx_PERF_SETUP" ||
		    "${board_rsrc}" == "DEV_CI_DATAPLANE_98xx_PERF_SETUP" ||
		    "${board_rsrc}" == "DEV_CI_DATAPLANE_106xx_PERF_SETUP")
			lock_dual_board_and_test(s, "${board_rsrc}", test_name, test_def)
		else
			lock_board_and_test(s, "${board_rsrc}", test_name, test_def)
	}

	tests.put(test_name, stg)
}

def prepare_asim_test_substage(Object s, tests, test_name, test_env, build_name, board_rsrc,
			       start_test_num, end_test_num) {
	def stg = {
		def bkp_src_dir = "${s.BUILD_BACKUP_ROOT}/src/${build_name}"
		def bkp_build_dir = "${s.BUILD_BACKUP_ROOT}/build/${build_name}"
		def build_dir = "${s.BUILD_DIR}/build/${build_name}"
		def src_dir = "${s.BUILD_DIR}/src/${build_name}"
		def run_dir = "${WORKSPACE}/${test_name}"

		stage ("Test: ${test_name}") {
			lock(label: "${board_rsrc}", variable: "asim_machine", quantity:'1') {
				println "Locked ASIM machines is ${env.asim_machine.trim()}"
				def asim_details="${env.asim_machine.trim()} 22"
				def tokens = asim_details.split()
				def target_asim = tokens[0]
				def target_asim_port = tokens[1]

				try {
					lock ("SYNC_LOCK") {
						sh script : """#!/bin/bash -x
						set -euo pipefail
						sudo mkdir -p ${s.BUILD_DIR}
						sudo chown -R jenkins:jenkins ${s.BUILD_DIR}
						mkdir -p ${src_dir}/
						mkdir -p ${build_dir}/
						rsync -a ${bkp_src_dir}/ ${src_dir}/
						rsync -a ${bkp_build_dir}/ ${build_dir}/

						cd ${src_dir}
						./marvell-ci/test/test.sh \
							-t ${src_dir}/marvell-ci/test/env/${test_env} \
							-r ${build_dir} \
							-d ${run_dir} \
							-p ${src_dir} \
							--list-only
						"""
					}
					sh (
						script: """#!/bin/bash -x
						set -euo pipefail

						cd ${src_dir}
						export TARGET_ASIM=ci@${target_asim}
						export TARGET_ASIM_PORT=${target_asim_port}
						export ASIM="/home/ci/asim-${s.REF_BRANCH}"
						export START_TEST_NUM=${start_test_num}
						export END_TEST_NUM=${end_test_num}
						export ASIM_REF_REMOTE_IMAGES="/home/ci/asim_target_images-${s.REF_BRANCH}"
						timeout --foreground -v -s 3 -k 30 480m \
							./marvell-ci/test/test.sh \
							-t ${src_dir}/marvell-ci/test/env/${test_env} \
							-r ${build_dir} \
							-d ${run_dir} \
							-p ${src_dir} \
							--run-only
						""",
						label: "Test ${test_name}"
					)
					s.utils.post_artifacts(test_name)
					s.TEST_STAGES_PASSED.push(test_name)
				} catch (err) {
					if (s.FAILING_FAST) {
						unstable ("Aborting as a parallel stage failed")
					} else {
						s.TEST_STAGES_FAILED.push(test_name)
						if (!s.utils.get_flag(s, "disable_failfast"))
							s.FAILING_FAST = true
						s.utils.post_artifacts(test_name)
						error "-E- Test ${test_name} failed, Exception err: ${err}"
					}
				}
			}
		}
	}

	tests.put(test_name, stg)
}

def prepare_asim_test_stage(Object s, tests, test_name, test_env, build_name, board_rsrc,
			    substage_name = null) {
	if (!s.utils.get_flag(s, "run_${test_name}"))
		return

	/* If substage name is given, run all the tests under that substage */
	if (substage_name) {
		prepare_asim_test_substage(s, tests, "${test_name}-SUBSTAGE-${substage_name}",
					   test_env, build_name, board_rsrc, 0, 999)
		return
	}

	/* If substage name is not given, split the tests into different substages */
	prepare_asim_test_substage(s, tests, "${test_name}-SUBSTAGE-1", test_env, build_name,
				   board_rsrc, 0, 34)
	prepare_asim_test_substage(s, tests, "${test_name}-SUBSTAGE-2", test_env, build_name,
				   board_rsrc, 35, 70)
	prepare_asim_test_substage(s, tests, "${test_name}-SUBSTAGE-3", test_env, build_name,
				   board_rsrc, 71, 105)
	prepare_asim_test_substage(s, tests, "${test_name}-SUBSTAGE-4", test_env, build_name,
				   board_rsrc, 106, 140)
	prepare_asim_test_substage(s, tests, "${test_name}-SUBSTAGE-5", test_env, build_name,
				   board_rsrc, 141, 999)
}

def prepare_tests(Object s, tests) {
	def num_tests

	if (s.utils.get_flag(s, "skip_test"))
		return 0

	/* CN9K Test */
	prepare_test_stage(s, tests, "test-cn9k", "cn9k.env", "test-cn9k-build",
				"DEV_CI_DATAPLANE_9xxx")

	/* CN96 Specific Test */
	prepare_test_stage(s, tests, "test-cn96", "cn96.env", "test-cn9k-build",
				"DEV_CI_DATAPLANE_96xx")

	/* CN9K Debug Test */
	prepare_test_stage(s, tests, "test-cn9k-debug", "cn9k.env", "test-cn9k-debug-build",
				"DEV_CI_DATAPLANE_9xxx")

	/* CN96 Perf Stage */
	prepare_test_stage(s, tests, "test-cn96-perf", "cn96-perf.env", "test-cn9k-build",
				"DEV_CI_DATAPLANE_96xx_PERF_SETUP")

	/* CN98 Perf Stage */
	prepare_test_stage(s, tests, "test-cn98-perf", "cn98-perf.env", "test-cn9k-build",
				"DEV_CI_DATAPLANE_98xx_PERF_SETUP")

	if (s.ENABLE_CN10K) {
		/* CN10K Test */
		prepare_test_stage(s, tests, "test-cn10k", "cn10k.env", "test-cn10k-build",
					"DEV_CI_DATAPLANE_106xx")

		/* CN10K Debug Test */
		prepare_test_stage(s, tests, "test-cn10k-debug", "cn10k.env", "test-cn10k-debug-build",
					"DEV_CI_DATAPLANE_106xx")

		/* CN10K Perf Stage */
		prepare_test_stage(s, tests, "test-cn106-perf", "cn106-perf.env", "test-cn10k-build",
					"DEV_CI_DATAPLANE_106xx_PERF_SETUP")

		/* ASIM Test Stage */
		prepare_asim_test_stage(s, tests, "test-asim-cn10ka", "asim-cn10ka.env",
					"test-cn10k-build", "DEV_CI_DATAPLANE_ASIM")
		prepare_asim_test_stage(s, tests, "test-asim-cn10ka", "asim-cn10ka-crypto.env",
					"test-cn10k-build", "DEV_CI_DATAPLANE_ASIM", "crypto")

		/* ASIM Debug Test Stage */
		prepare_asim_test_stage(s, tests, "test-asim-cn10ka-debug", "asim-cn10ka.env",
					"test-cn10k-debug-build", "DEV_CI_DATAPLANE_ASIM")
		prepare_asim_test_stage(s, tests, "test-asim-cn10ka-debug", "asim-cn10ka-crypto.env",
					"test-cn10k-debug-build", "DEV_CI_DATAPLANE_ASIM", "crypto")
	}

	num_tests = tests.size()

	if (!s.utils.get_flag(s, "disable_failfast"))
		tests.failFast = true

	return num_tests
}

def run(Object s) {
	def tests = [:]
	def num_tests

	num_tests = prepare_tests(s, tests)
	if (num_tests > 0) {
		node (s.NODE_LABEL_TEST) {
			lock(env.NODE_NAME) {
				s.utils.print_env(s)
				stage ("Test") {
					def failed = false

					/* Initialisations for tests */
					sh script: """#!/bin/bash -x
					set -euo pipefail
					sudo mkdir -p ${s.BUILD_DIR}
					sudo chown -R jenkins:jenkins ${s.BUILD_DIR}
					"""
					try {
						parallel(tests)
					} catch (err) {
						failed = true
					}

					/* Slack report for nightly tests */
					if (s.utils.get_flag(s, "nightly_test")) {
						def report

						report  = "=======================================\n"
						report += "${env.GERRIT_BRANCH} CI Nightly Test Report\n"
						report += "=======================================\n"
						report += "\n"
						report += "Link: ${env.RUN_DISPLAY_URL}\n"
						report += "\n"
						report += "Tests Passed\n"
						report += "------------\n"
						for (t in s.TEST_STAGES_PASSED)
							report += "${t}\n"
						report += "\n"
						report += "Tests Failed\n"
						report += "------------\n"
						for (t in s.TEST_STAGES_FAILED)
							report += "${t}\n"
						s.utils.message_slack(s, "$report", failed)
					}

					if (failed)
						error "-E- Test stages failed"
				}
			}
		}
	}
}

return this
