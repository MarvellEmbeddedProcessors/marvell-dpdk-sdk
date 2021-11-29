/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

def check_roc(Object s) {
	stage ('ROC Check') {
		def roc_path = "drivers/common/cnxk"
		def roc_changes = true
		def non_roc_changes = true
		try {
			sh (
				script: """#!/bin/bash

				cd ${s.PROJECT_ROOT}
				FILES_CHANGED=\$(git show --pretty="" --name-only HEAD | \
					grep "$roc_path")

				if [[ -n \$FILES_CHANGED ]]; then
					echo "ROC files changed"
					exit 0
				fi
				echo "ROC files not changed"
				exit 1
				""",
				label: "Checking whether ROC files were changed"
			)
		} catch (err) {
			roc_changes = false
		}

		try {
			sh (
				script: """#!/bin/bash

				cd ${s.PROJECT_ROOT}
				FILES_CHANGED=\$(git show --pretty="" --name-only HEAD | \
					grep -v "$roc_path")

				if [[ -n \$FILES_CHANGED ]]; then
					echo "Non ROC files changed"
					exit 0
				fi
				echo "Non ROC files not changed"
				exit 1
				""",
				label: "Checking whether Non ROC files were changed"
			)
		} catch (err) {
			non_roc_changes = false
		}

		if (roc_changes && non_roc_changes) {
			if (!s.utils.get_flag(s, "skip_roc_check")) {
				def err = "-E- Patch contains both ROC and Non ROC changes. "
				err += "Split ROC changes into a separate commit."
				error(err)
			}
		}

		if (roc_changes) {
			def msg = "REMINDER: This patch contains ROC changes. "
			msg += "Sync the changes to ODP as well if not already done !!!"
			s.utils.gerrit_add_comment(s, msg)
		}
	}
}

def check_patch(Object s) {
	stage ("Checkpatch") {
		try {
			sh (
				script: """#!/bin/bash
				cd ${s.PROJECT_ROOT};
				git log -1
				timeout --foreground -v -k 30 1m \
					./marvell-ci/checkpatch/run_checkpatch.sh
				""",
				label: "Checkpatch test"
			)
		} catch (err) {
			if (!s.utils.get_flag(s, "skip_checkpatch"))
				error "-E- Checkpatch Failed, Exception err: ${err}"
		}
	}
}

def check_format(Object s) {
	stage ("Checkformat") {
		try {
			sh (
				script: """#!/bin/bash
				cd ${s.PROJECT_ROOT}
				git log -1
				timeout --foreground -v -k 30 1m \
					./marvell-ci/checkpatch/run_checkformat.sh
				""",
				label: "Check format test"
			)
		} catch (err) {
			if (!s.utils.get_flag(s, "skip_checkformat"))
				error "-E- Check Format Failed, Exception err: ${err}"
		}
	}
}

def check_sanity(Object s) {
	stage ("Check Sanity") {
		try {
			sh (
				script: """#!/bin/bash
				cd ${s.PROJECT_ROOT}
				./marvell-ci/checkpatch/run_check_sanity.sh
				""",
				label: "Check Sanity"
			)
		} catch (err) {
			if (!s.utils.get_flag(s, "skip_check_sanity"))
				error "-E- Sanity Check Failed, Exception err: ${err}"
		}
	}
}

def run(Object s) {
	stage ('Check') {
		def stages = [:]
		stages.put('Check Sanity', {check_sanity(s)})
		stages.put('Checkformat', {check_format(s)})
		stages.put('Checkpatch', {check_patch(s)})
		stages.put('ROC Check', {check_roc(s)})
		parallel(stages)
	}
}

return this
