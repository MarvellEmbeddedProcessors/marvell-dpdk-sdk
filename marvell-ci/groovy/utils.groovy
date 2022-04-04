/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

import org.jenkins.plugins.lockableresources.LockableResourcesManager as LRM
import org.jenkins.plugins.lockableresources.LockableResource
import groovy.json.JsonSlurperClassic

def get_flag(Object s, flag) {
	try {
		if (s.flags[flag][1])
			return true
	} catch (err) {
	}
	return false
}

def set_flag(Object s, flag, val) {
	def flag_set = true
	try {
		s.flags[flag][1] = val
	} catch (err) {
		flag_set = false
	}
	return flag_set
}

@NonCPS
def remove_board(board, job) {
	def lrm = LRM.get()
	List<LockableResource> lr_list = new ArrayList<LockableResource>()
	LockableResource lr = lrm.fromName(board)

	lr_list.add(lr)
	if (!lrm.reserve(lr_list, "Job ${job} (Inaccessible)"))
		print "Removing ${board} failed"

	lrm.save()
}

@NonCPS
def get_boards(board_rsrc) {
	def lrm = LRM.get()
	List<String> boards = new ArrayList<String>()
	List<LockableResource> lr_list = lrm.getResourcesWithLabel(board_rsrc, null)

	for (lr in lr_list)
		boards.add(lr.getName())

	return boards
}

def message_slack(Object s, message, broadcast = false) {
	def b = broadcast ? "1" : ""
	try {
		sh script : """#!/bin/bash
			export BROADCAST=${b}
			${s.SCRIPTS_CACHE_DIR}/message_slack.sh '${message}'
		"""
	} catch (err) {
		print "Failed to message slack [Err: $err]"
	}
}

def setup_board(Object s, board, force = false) {
	def force_reboot = force ? "--force-reboot" : ""
	try {
		sh script: """#!/bin/bash
		cd ${s.PROJECT_ROOT}
		python3 ./marvell-ci/test/board/board_setup.py ${force_reboot} --ssh-ip ${board}
		"""
	} catch (err) {
		return false
	}
	return true
}

def post_artifacts(dir) {
	try {
		archiveArtifacts artifacts: "${dir}/*"
	} catch (err) {
		println "Caught '${err}' while trying to post artifacts at ${dir}"
	}
}

@NonCPS
def parse_json(text) {
	try {
		def jsonSlurper = new JsonSlurperClassic()
		return jsonSlurper.parseText(text)
	} catch(err) {
		return null
	}
}

def gerrit_rest_command(Object s, command, options = "") {
	def result = sh (
		script: """#!/bin/bash
			curl -k --netrc-file ${s.NETRC_FILE} $options\
				https://${env.GERRIT_HOST}/a/${command} 2>/dev/null | tail +2
			""",
		returnStdout: true
	).trim()

	return parse_json(result)
}

def gerrit_get_ancestor(Object s) {
	def related = gerrit_rest_command(s, "changes/${env.GERRIT_CHANGE_NUMBER}/revisions/${env.GERRIT_PATCHSET_NUMBER}/related")
	def ancestor = "HEAD~1"

	if (related.changes.size() != 0)
		ancestor = related.changes.last().commit.parents.first().commit

	println "Ancestor Commit is ${ancestor}"

	return ancestor
}

def gerrit_add_comment(Object s, comment) {
	def command = "changes/${env.GERRIT_CHANGE_NUMBER}/revisions/${env.GERRIT_PATCHSET_NUMBER}/review"
	def options = "--header \"Content-Type: application/json;charset=UTF-8\" "
	options += "--request POST --data '{\"message\":\"$comment\"}'"
	gerrit_rest_command(s, command, options)
}

def gerrit_is_head_commit(Object s) {
	def related = gerrit_rest_command(s, "changes/${env.GERRIT_CHANGE_NUMBER}/revisions/${env.GERRIT_PATCHSET_NUMBER}/related")
	def cur_commit = gerrit_rest_command(s, "changes/${env.GERRIT_CHANGE_NUMBER}/revisions/${env.GERRIT_PATCHSET_NUMBER}/commit")
	def next_change
	def next_change_details
	def changes = ""

	/* There are no related changes */
	if (related.changes.size() == 0) {
		println("Related Changes - None")
		return true
	}

	for(def change : related.changes)
		changes += change._change_number + " "
	println("Related Changes - ${changes}")

	/* This change is not first among the related changes. Make sure the
	 * following regarding the change just above this one before calling
	 * this one as a non-head commit.
	 * 1. Has its latest revision. This is to check for the case where the
	 *    change above the current one gets updated but not the current one.
	 *    Happens when the above change becomes part of another review
	 *    series.
	 * 2. The parent is current change.  This is to check for the case where
	 *    the current change gets updated but not the ones above it.
	 * 3. State should be 'NEW', i.e the ones above it should not be
	 *    in abandoned, merged, wip state etc.
	 */
	next_change = related.changes.first()
	for(def change : related.changes) {
		if (change.commit.commit == cur_commit.commit)
			break
		next_change = change
	}

	if (next_change.commit.commit == cur_commit.commit)
		return true

	if (next_change._revision_number != next_change._current_revision_number)
		println("Next commit revision is not it's latest one")

	if (next_change.status != 'NEW')
		println("Next commit status is not NEW")

	if (next_change.commit.parents.first().commit != cur_commit.commit)
		println("Next commit's parent is not current commit")

	next_change_details = gerrit_rest_command(s, "changes/${next_change._change_number}")
	if (next_change_details.work_in_progress != null &&
	    next_change_details.work_in_progress == true)
		println("Next commit WIP state is true")

	return false
}

def setup_toolchains(Object s) {
	s.TOOLCHAIN_TARBALL="${s.NFS_MOUNT}/toolchain_cache/gcc-10-marvell-1013.0/marvell-tools-1013.0.tar.bz2"
	s.TOOLCHAIN_NAME="gcc-10-marvell-1013.0"
	s.TOOLCHAIN_DIR="${s.HOST_MOUNT}/prebuilt/toolchain/gcc-10-marvell-1013.0"

	try {
		lock(resource: "TOOLCHAIN_SETUP_LOCK") {
			sh (
			script: """#!/bin/bash
			if [[ ! -d ${s.TOOLCHAIN_DIR} ]]; then
				cp ${s.TOOLCHAIN_TARBALL} /tmp/toolchain.tar.bz2
				echo "Setting up toolchain at ${s.TOOLCHAIN_DIR}"
				mkdir -p ${s.TOOLCHAIN_DIR}
				tar -jxvf /tmp/toolchain.tar.bz2 -C ${s.TOOLCHAIN_DIR} \
					--strip-components=1
			else
				echo "Toolchain present at ${s.TOOLCHAIN_DIR}"
			fi
			""",
			label: "Setup Internal Toolchain ${s.TOOLCHAIN_NAME}"
			)
		}
	} catch (err) {
		error "-E- Failed to setup Internal Toolchain ${s.TOOLCHAIN_NAME}, Exception err: ${err}"
	}

	try {
		sh (
			script: """#!/bin/bash
			set -x
			cd ${s.PROJECT_ROOT}
			sudo PKG_CACHE_DIR=${s.DEPS_SRC_CACHE_DIR} \
				./marvell-ci/toolchain/setup_distro_toolchains.sh
			""",
			label: "Setup Distro Toolchains"
		)
	} catch (err) {
		error "-E- Failed to setup distro toolchains, Exception err: ${err}"
	}
}

def print_env(Object s) {
	sh script: """#!/bin/bash
	echo "#####################"
	echo "Environment Variables"
	echo "#####################"
	env
	"""
}


def stage_node(Object s, nodes, name, stage_exec, run_on_he = true, strict_he = false) {
	def node_def

	node_def = {
		stage (name) {
			def completed = false

			if (run_on_he) {
				/*
				 * Try to first run on a high-end (HE) machine. If its not
				 * available, then switch back to normal servers unless
				 * it was asked to strictly run on HE machines.
				 */
				lock(label: "DEV_CI_DATAPLANE_ASIM", variable: "mc", quantity:'1',
				     skipIfLocked : !strict_he) {
					println "Locked HE machine is ${env.mc.trim()}"
					def mc_details="${env.mc.trim()} 22"
					def tokens = mc_details.split()
					def mc_ip = tokens[0]
					node ("$mc_ip") {
						lock(env.NODE_NAME) { /* Only for debugging */
							print_env(s)
							stage_exec()
						}
					}
					completed = true
				}
			}
			if (!completed) {
				/* High end machine was not available, run on any other available
				 * machine */
				node (s.NODE_LABEL_ME) {
					lock(env.NODE_NAME) { /* Only for debugging */
						print_env(s)
						stage_exec()
					}
				}
			}
		}
	}

	nodes.put(name, node_def)
}

def add_stage_node_he(Object s, nodes, name, stage_exec) {
	stage_node(s, nodes, name, stage_exec, true, true)
}

def add_stage_node_me(Object s, nodes, name, stage_exec) {
	stage_node(s, nodes, name, stage_exec, false)
}

def add_stage_node(Object s, nodes, name, stage_exec) {
	stage_node(s, nodes, name, stage_exec)
}

return this
