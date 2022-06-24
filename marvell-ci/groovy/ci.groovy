/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

/*
 * Syntax documentation: https://www.jenkins.io/doc/book/pipeline/syntax.
 * Note that Jenkins is using Scripted Pipeline, so not all constructs are
 * available.
 */

def execute_ci(Object s) {
	node (s.NODE_LABEL) {
		def groovy_dir
		def tmp_path

		/*
		 * Create a copy of the project source in the shared NFS space so that each stage
		 * need not checkout the source again and again.
		 */

		s.JOB_ROOT = "/data/isoc_platform_devops/dev-ci/jobs/${env.JOB_NAME}/${env.BUILD_NUMBER}/"
		s.PROJECT_ROOT = "${s.JOB_ROOT}/sources/$GERRIT_PROJECT"
		s.BUILD_BACKUP_ROOT = "${s.JOB_ROOT}/builds/"
		s.project = s.components_map[this.params.component_name]
		s.checkout_patch(s)
		tmp_path = s.project.srcdir()
		sh script : """#!/bin/bash
			set -euo pipefail
			ls ${tmp_path}
			mkdir -p ${s.PROJECT_ROOT}
			rsync -a ${tmp_path}/ ${s.PROJECT_ROOT}/
		"""

		/* Load groovy scripts */
		groovy_dir = "${tmp_path}/marvell-ci/groovy/"

		s.utils = load groovy_dir + "utils.groovy"
		s.init = load groovy_dir + "init.groovy"
		s.check = load groovy_dir + "check.groovy"
		s.setup = load groovy_dir + "setup.groovy"
		s.build = load groovy_dir + "build.groovy"
		s.test = load groovy_dir + "test.groovy"
		s.verify = load groovy_dir + "verify.groovy"

		s.init.run(s)
		s.check.run(s)
		s.setup.run(s)
	}

	/* The nodes are controlled within the s.build.run()/s.test.run() function.
	 * No need to wrap these calls in a node */
	s.build.run(s)
	s.test.run(s)

	node (s.NODE_LABEL) {
		s.verify.run(s)
		sh script : """#!/bin/bash
			set -euo pipefail
			rm -rf ${s.JOB_ROOT}
		"""
	}
}

def run_ci(Object s) {
	s.NODE_LABEL="buildenv-2004-me"

	try {
		execute_ci(s)
	} catch (err) {
		node (s.NODE_LABEL) {
			sh script : """#!/bin/bash
				set -euo pipefail
				rm -rf ${s.JOB_ROOT}
			"""
		}
		error "CI failed with error ${err}"
	}
}

return this
