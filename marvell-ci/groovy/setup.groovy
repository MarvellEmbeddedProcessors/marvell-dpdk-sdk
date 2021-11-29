/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

def add_reviewers(Object s) {
	stage ('Add Reviewers') {
		try {
			def URL="https://${env.GERRIT_HOST}/a/changes/${env.GERRIT_CHANGE_NUMBER}/reviewers"
			def ancestor = s.utils.gerrit_get_ancestor(s)
			sh (
				script: """#!/bin/bash
				cd ${s.PROJECT_ROOT}
				AUTHORS=""
				FILES_CHANGED=`git show --pretty="" --name-only HEAD`
				HEAD_COMMIT=`git show --pretty="" --oneline HEAD | head -n1 | awk '{print \$1}'`
				for F in \$FILES_CHANGED; do
					echo "#############################################"
					echo "\$F"
					echo "--------------- Adjacent Lines --------------"
					git blame HEAD -e \$F | grep -A 1 -B 1 \$HEAD_COMMIT

					git blame HEAD -e \$F | awk '{\$6=""; print }' > blame.txt
					ADJ_LINES_OWNERS=`cat blame.txt | grep -A 1 -B 1 \$HEAD_COMMIT | \
							  sed -r "s/>/</g" | awk -F'<' '{print \$2}' | sort | uniq`
					AUTHORS="\$AUTHORS\n\$ADJ_LINES_OWNERS"
					rm blame.txt
					CHANGED_LINES=\$(git difftool --no-prompt --extcmd \
								"diff --changed-group-format='%dF,+%dN ' \
								--unchanged-group-format=''" ..${ancestor} -- \$F \
							)

					echo "--------------- Changed Lines ---------------"
					echo "Info: \$F \$CHANGED_LINES"

					for LC in \$CHANGED_LINES; do
						echo "------------ Lines \$LC -------------"
						git blame -e -L\$LC ${ancestor} -- \$F

						LINES_OWNERS=\$(git blame -e -L\$LC ${ancestor} -- \$F | \
									sed -r "s/>/</g" | awk -F'<' '{print \$2}' | \
									sort | uniq \
								)
						AUTHORS="\$AUTHORS\n\$LINES_OWNERS"
					done
				done

				AUTHORS=`echo -e "\$AUTHORS" | sort | uniq | grep marvell`
				for A in \$AUTHORS; do
					curl -k --netrc-file ${s.NETRC_FILE} -X POST \
						-H 'Content-Type: application/json; charset=UTF-8' \
						-d "{reviewer: \$A}" \
						${URL} 2>/dev/null 1>out.json
					err=`grep error out.json`
					if [ -n "\$err" ]; then
						echo "Failed to add \$A as a reviewer"
					else
						echo "Successfully added \$A as a reviewer"
					fi
				done
				""",
				label: "Adding reviewers"
			)
		} catch (err) {
			println "-E- Failed to add reviewers: ${err}"
		}
	}
}

def run(Object s) {
	if (s.utils.get_flag(s, "skip_add_reviewers"))
		return

	stage ("Add Reviewers") {
		add_reviewers(s)
	}
}

return this
