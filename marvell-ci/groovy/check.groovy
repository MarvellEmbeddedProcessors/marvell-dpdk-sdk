/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

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
		parallel(stages)
	}
}

return this
