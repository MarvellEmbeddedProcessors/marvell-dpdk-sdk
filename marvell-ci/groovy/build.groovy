/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

def build_stage_node(Object s, nodes, name, stage_exec) {
	def node_def

	node_def = {
		stage (name) {
			node (s.NODE_LABEL_BUILD) {
				lock(env.NODE_NAME) { /* Only for debugging */
					s.utils.print_env(s)
					stage_exec()
				}
			}
		}
	}

	nodes.put(name, node_def)
}

def add_doc_build_stage(Object s, nodes)
{
	def build_name = 'doc-build'

	def stg = {
		def ci_logdir = "${WORKSPACE}/${build_name}"
		def src_dir = "${s.BUILD_DIR}/src/${build_name}"
		def build_dir = "${s.BUILD_DIR}/build/${build_name}"
		try {
			utils.setup_toolchains(s)
			sh (
				script: """#!/bin/bash -x
				set -euo pipefail
				sudo mkdir -p ${s.BUILD_DIR}
				sudo chown -R jenkins:jenkins ${s.BUILD_DIR}
				mkdir -p ${src_dir}
				mkdir -p ${build_dir}
				mkdir -p ${ci_logdir}
				"""
			)
			lock ("SYNC_LOCK") {
				sh (
					script: """#!/bin/bash -x
					set -euo pipefail
					rsync -a ${s.PROJECT_ROOT}/ ${src_dir}/
					"""
				)
			}
			sh (
				script: """#!/bin/bash -x
				set -euo pipefail
				cd ${src_dir}
				MAKE_J=2

				./marvell-ci/build/build.sh \
					-b ./marvell-ci/build/env/x86-gcc.env \
					-r ${build_dir} \
					-p ${src_dir} \
					-m "-Denable_docs=true" \
					-j \$MAKE_J

				cd ${build_dir}/prefix/share/doc/dpdk/
				tar -zcf ${ci_logdir}/dpdk-docs.tar.gz html
				""",
				label: "Build DPDK Docs"
			)
		} catch (err) {
			if (s.FAILING_FAST) {
				unstable ("Aborting as a parallel stage failed")
			} else {
				if (!s.utils.get_flag(s, "disable_failfast"))
					s.FAILING_FAST = true
				error "-E- Failed to build DPDK Docs, Exception err: ${err}"
			}
		}

		try {
			sh (
				script: """#!/bin/bash -x
				set -euo pipefail
				cd ${src_dir}/marvell-ci/doc
				make
				cd build
				tar -zcf ${ci_logdir}/marvell-ci-docs.tar.gz html
				""",
				label: "Build Marvell CI Docs"
			)
		} catch (err) {
			if (s.FAILING_FAST) {
				unstable ("Aborting as a parallel stage failed")
			} else {
				if (!s.utils.get_flag(s, "disable_failfast"))
					s.FAILING_FAST = true
				error "-E- Failed to build Marvell CI Docs, Exception err: ${err}"
			}
		}

		s.utils.post_artifacts(build_name)
	}

	build_stage_node(s, nodes, build_name, stg)
}

def add_klocwork_stage(Object s, nodes)
{
	def build_name = 'klocwork-build'

	def stg = {
		def ci_logdir = "${WORKSPACE}/klocwork"
		def build_dir = "${s.BUILD_DIR}/build/${build_name}"
		def src_dir = "${s.BUILD_DIR}/src/${build_name}"

		try {
			utils.setup_toolchains(s)

			sh (
				script: """#!/bin/bash -x
				set -euo pipefail
				sudo mkdir -p ${s.BUILD_DIR}
				sudo chown -R jenkins:jenkins ${s.BUILD_DIR}
				mkdir -p ${build_dir}
				mkdir -p ${src_dir}
				mkdir -p ${ci_logdir}
				"""
			)
			lock ("SYNC_LOCK") {
				sh (
					script: """#!/bin/bash -x
					set -euo pipefail
					rsync -a ${s.PROJECT_ROOT}/ ${src_dir}/curr/
					rsync -a ${s.PROJECT_ROOT}/ ${src_dir}/prev/
					"""
				)
			}
			sh (
				script: """#!/bin/bash -x
				MAKE_J=2

				export PATH=${s.TOOLCHAIN_DIR}/bin:/home/jenkins/klocwork/kwbin/bin:$PATH

				cd ${src_dir}/curr
				./marvell-ci/klocwork/klocwork.sh \
					-r ${build_dir}/curr \
					-p ${src_dir}/curr \
					-j \$MAKE_J | \
						tee ${build_dir}/curr.txt
				cp ./kwreport-detailed.txt ${ci_logdir}/kwreport-curr.txt

				cd ${src_dir}/prev
				git checkout HEAD~1
				./marvell-ci/klocwork/klocwork.sh \
					-r ${build_dir}/prev \
					-p ${src_dir}/prev \
					-j \$MAKE_J | \
						tee ${build_dir}/prev.txt
				cp ./kwreport-detailed.txt ${ci_logdir}/kwreport-prev.txt

				cd ${src_dir}/curr
				python3 ./marvell-ci/klocwork/klocwork_report_sort.py \
					${src_dir}/curr ${ci_logdir}/kwreport-curr.txt \
					> curr.tmp
				python3 ./marvell-ci/klocwork/klocwork_report_sort.py \
					${src_dir}/prev ${ci_logdir}/kwreport-prev.txt \
					> prev.tmp
				diff curr.tmp prev.tmp > ${ci_logdir}/kwreport-diff.txt || true

				CURR_ISSUE_CNT=\$(grep 'Klocwork CNXK Issues:' ${build_dir}/curr.txt | awk '{print \$4}')
				PREV_ISSUE_CNT=\$(grep 'Klocwork CNXK Issues:' ${build_dir}/prev.txt | awk '{print \$4}')
				echo "Current issue count: \$CURR_ISSUE_CNT"
				echo "Previous issue count: \$PREV_ISSUE_CNT"
				if [ \$CURR_ISSUE_CNT -gt \$PREV_ISSUE_CNT ]; then
					echo "Klocwork Check Failed. New issues found !"
					exit 1
				fi
				echo "Klocwork Check Passed. No new issues!"
				""",
				label: "Klocwork"
			)
			s.utils.post_artifacts("klocwork")
		} catch (err) {
			if (s.FAILING_FAST) {
				unstable ("Aborting as a parallel stage failed")
			} else {
				if (!s.utils.get_flag(s, "disable_failfast"))
					s.FAILING_FAST = true
				s.utils.post_artifacts("klocwork")
				error "-E- Klocwork check failed, Exception err: ${err}"
			}
		}
	}

	build_stage_node(s, nodes, build_name, stg)
}

def get_build_params(build_name, compiler, libtype, copt, clinkopt, arch, extra_args)
{
	def name
	def args = "${extra_args} "

	name = build_name
	if (name == "")
		name = "build-${arch}-${compiler}-${libtype}${copt}${clinkopt}"

	if (libtype == "shared")
		args += "--default-library=shared "

	if (clinkopt == "-lto")
		clinkopt = "-flto"

	return [name, args, clinkopt]
}

def add_build_stage(Object s, nodes, build_name, compiler, libtype, copt, clinkopt, arch,
		    extra_args = "", patches = "", backup = false, strict_me = false,
		    strict_he = false)
{
	def params = get_build_params(build_name, compiler, libtype, copt, clinkopt, arch,
				      extra_args)
	def name = params[0]

	def stg = {
		def args = params[1]
		def build_dir = "${s.BUILD_DIR}/build/${name}"
		def src_dir = "${s.BUILD_DIR}/src/${name}"
		def bkp_build_dir = "${s.BUILD_BACKUP_ROOT}/build/${name}"
		def bkp_src_dir = "${s.BUILD_BACKUP_ROOT}/src/${name}"
		def build_root = "${s.BUILD_DIR}/${name}"
		clinkopt = params[2]

		try {
			utils.setup_toolchains(s)

			sh (
				script: """#!/bin/bash -x
				set -euo pipefail
				sudo mkdir -p ${s.BUILD_DIR}
				sudo chown -R jenkins:jenkins ${s.BUILD_DIR}

				mkdir -p ${src_dir}/
				mkdir -p ${build_dir}
				"""
			)
			lock ("SYNC_LOCK") {
				sh (
					script: """#!/bin/bash -x
					set -euo pipefail
					rsync -a ${s.PROJECT_ROOT}/ ${src_dir}/
					"""
				)
			}
			sh (
				script: """#!/bin/bash -x
				set -euo pipefail
				cd ${src_dir}

				./marvell-ci/patches/apply_patches.sh ${patches}

				if [[ ${compiler} == gcc-marvell ]]; then
					export PATH=${s.TOOLCHAIN_DIR}/bin:$PATH
				fi

				export PKG_CACHE_DIR=${s.DEPS_SRC_CACHE_DIR}
				export CFLAGS="${copt}"
				export LDFLAGS="${clinkopt}"
				MAKE_J=2
				./marvell-ci/build/build.sh \
					-b ./marvell-ci/build/env/${arch}-${compiler}.env \
					-r ${build_dir} \
					-p ${src_dir} \
					-j \$MAKE_J \
					-m "${args}"
				""",
				label: "Build ${name}"
			)
		} catch (err) {
			if (s.FAILING_FAST) {
				unstable ("Aborting Build as a parallel stage failed")
			} else {
				if (!s.utils.get_flag(s, "disable_failfast"))
					s.FAILING_FAST = true
				error "-E- Failed to build ${name}, Exception err: ${err}"
			}
		}

		if (backup) {
			lock ("SYNC_LOCK") {
				sh (
					script: """#!/bin/bash -x
					set -euo pipefail
					mkdir -p ${bkp_src_dir}
					mkdir -p ${bkp_build_dir}
					rsync -a ${src_dir}/ ${bkp_src_dir}/
					rsync -a ${build_dir}/ ${bkp_build_dir}/
					""",
					label: "Backup Build"
				)
			}
		}
	}

	build_stage_node(s, nodes, name, stg)
}

def prepare_build_stages(Object s, nodes, compilers, libtypes, copts, clinkopts, archs, extra_args,
			 patches = "")
{
	for (c in compilers) {
		for (t in libtypes) {
			for (o in copts) {
				for (l in clinkopts) {
					for (a in archs) {
						add_build_stage(s, nodes, "", c, t, o, l, a,
								extra_args, patches)
					}
				}
			}
		}
	}
}

def prepare_builds(Object s, nodes) {
	/* Builds used in test stages */
	if (!s.utils.get_flag(s, "skip_test")) {
		/* CN9k Test builds */
		if (s.utils.get_flag(s, "run_test-cn9k") ||
		    s.utils.get_flag(s, "run_test-cn96") ||
		    s.utils.get_flag(s, "run_test-cn96-perf") ||
		    s.utils.get_flag(s, "run_test-cn98-perf"))
			add_build_stage(s, nodes, "test-cn9k-build", 'gcc-marvell', 'static',
					'-O3', '-lto', 'cn9k', '-Dexamples=all', '', true)
	}

	if (s.ENABLE_CN10K) {
		/* cn10k test builds */
		if (s.utils.get_flag(s, "run_test-cn10k") ||
		    s.utils.get_flag(s, "run_test-cn106-perf") ||
		    s.utils.get_flag(s, "run_test-asim-cn10ka") ||
		    !s.utils.get_flag(s, "skip_build"))
			add_build_stage(s, nodes, "test-cn10k-build", 'gcc-marvell',
					'static', '-O3', '-lto', 'cn10k', '-Dexamples=all',
					'', true)
	}

	if (!s.utils.get_flag(s, "skip_build")) {
		/* Klocwork Build */
		if (!s.utils.get_flag(s, "skip_klocwork"))
			add_klocwork_stage(s, nodes)

		/* x86 Builds */
		prepare_build_stages(s, nodes, ['clang', 'gcc-4.8', 'gcc'], ['static'],
					     ['-O3'], [''], ['x86'], '-Dexamples=all')
		prepare_build_stages(s, nodes, ['gcc'], ['shared'],
					     ['-O3'], [''], ['x86'], '-Dexamples=all')
		prepare_build_stages(s, nodes, ['gcc'], ['static'],
					     ['-O0'], [''], ['x86'], '-Dexamples=all')
		prepare_build_stages(s, nodes, ['gcc'], ['static'],
					     ['-O3'], ['-lto'], ['x86'], '-Dexamples=all')

		/* Generic armv8 Builds */
		prepare_build_stages(s, nodes, ['clang'], ['static'],
					     ['-O3'], [''], ['armv8'], '-Dexamples=all')
		prepare_build_stages(s, nodes, ['gcc-4.8'], ['static'],
					     ['-O3'], [''], ['armv8'],
					     '-Ddisable_drivers=event/cnxk',
					     'armv8-gcc-4.8-fix')
		prepare_build_stages(s, nodes, ['gcc'], ['static'],
					     ['-O3'], [''], ['armv8'], '-Dexamples=all')

		/* CN9K Build */
		prepare_build_stages(s, nodes, ['gcc-marvell'], ['static'],
				     ['-O3'], ['-lto'], ['cn9k'], '-Dexamples=all')

		if (s.ENABLE_CN10K) {
			/* CN10k Builds */
			prepare_build_stages(s, nodes, ['gcc-marvell'], ['static', 'shared'],
					     ['-O3'], ['-lto', ''], ['cn10k'], '-Dexamples=all')
			prepare_build_stages(s, nodes, ['gcc-marvell'], ['static', 'shared'],
					     ['-O0'], ['-lto', ''], ['cn10k'], '-Dexamples=all')
			prepare_build_stages(s, nodes, ['clang'], ['shared'],
					     ['-O3'], [''], ['cn10k'], '-Dexamples=all')
		}

		/* Doc Build */
		add_doc_build_stage(s, nodes)

	}

	/* CN9k Debug Build */
	if (!s.utils.get_flag(s, "skip_build") ||
	    (!s.utils.get_flag(s, "skip_test") && s.utils.get_flag(s, "run_test-cn9k-debug")))
		add_build_stage(s, nodes, "test-cn9k-debug-build", 'gcc-marvell',
			'static', '-O0 -DRTE_ENABLE_ASSERT',
			'', 'cn9k',
			"-Dexamples=all --buildtype=debug --werror",
			'', false)

	/* CN10k Debug Build */
	if (s.ENABLE_CN10K && (!s.utils.get_flag(s, "skip_build") ||
	    (!s.utils.get_flag(s, "skip_test") && (s.utils.get_flag(s, "run_test-cn10k-debug") ||
		(s.utils.get_flag(s, "run_test-asim-cn10ka-debug"))))))
		add_build_stage(s, nodes, "test-cn10k-debug-build", 'gcc-marvell',
			'static', '-O0 -DRTE_ENABLE_ASSERT', '', 'cn10k',
			"-Dexamples=all --buildtype=debug --werror",
			'', false)

}

def run(Object s) {
	def nodes = [:]

	s.BUILD_DIR = "/ci_build"

	prepare_builds(s, nodes)
	if (!s.utils.get_flag(s, "disable_failfast"))
		nodes.failFast = true

	if (nodes.size() > 0) {
		stage ("Build") {
			parallel(nodes)
		}
	}
}

return this
