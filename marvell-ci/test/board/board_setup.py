# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

import pexpect
import time
import sys
import os
import argparse

class Telnet:
	def __init__(self, host, port, connlog = None):
		self.conn = pexpect.spawn("telnet %s %s" %(host, port))
		if connlog != None:
			self.conn.logfile_read = open(connlog, 'wb')
		else:
			self.conn.logfile_read = None
		self.conn.logfile_send = None
		self.conn.delaybeforesend = 0.5
		self.timeout = 10
		self.expect(["Connected to.*","<CTRL>Z"], self.timeout)

	def close(self):
		self.conn.close()
		if self.conn.logfile_read:
			self.conn.logfile_read.close()

	def send(self, str):
		self.conn.sendline(str)

	def expect(self, pattern, timeout = None):
		if timeout == None:
			timeout = self.timeout
		return self.conn.expect(pattern, timeout)

class SSH:
	def __init__(self, host, username, password, connlog = None):
		self.conn = pexpect.spawn("%s %s@%s" % (os.environ.get('TARGET_SSH_CMD', 'ssh'), username, host))
		if connlog != None:
			self.conn.logfile_read = open(connlog, 'wb')
		else:
			self.conn.logfile_read = None
		self.conn.logfile_send = None
		self.conn.delaybeforesend = 0.5
		self.timeout = 10
		self.expect("password:", self.timeout)
		self.send(str(password))
		self.conn.expect("Welcome to", self.timeout)
		self.conn.expect("#", self.timeout)

	def close(self):
		self.conn.close()
		if self.conn.logfile_read:
			self.conn.logfile_read.close()

	def send(self, str):
		self.conn.sendline(str)

	def expect(self, pattern, timeout = None):
		if timeout == None:
			timeout = self.timeout
		return self.conn.expect(pattern, timeout)


class Board:
	def __init__(self, ssh_ip, ssh_username, ssh_password, mcu_telnet_ip, mcu_telnet_port,
		     mcu_board_telnet_port, pdu_ssh_ip, pdu_ssh_username, pdu_ssh_password,
		     pdu_outlet, bmc_ssh_ip, bmc_ssh_username, bmc_ssh_password):
		self.ssh_ip = ssh_ip
		self.ssh_username = ssh_username
		self.ssh_password = ssh_password
		self.mcu_telnet_ip = mcu_telnet_ip
		self.mcu_telnet_port = mcu_telnet_port
		self.mcu_board_telnet_port = mcu_board_telnet_port
		self.pdu_ssh_ip = pdu_ssh_ip
		self.pdu_ssh_username = pdu_ssh_username
		self.pdu_ssh_password = pdu_ssh_password
		self.pdu_outlet = pdu_outlet
		self.bmc_ssh_ip = bmc_ssh_ip
		self.bmc_ssh_username = bmc_ssh_username
		self.bmc_ssh_password = bmc_ssh_password
		self.board_log = "board.log"

	def setup(self):
		if self.test_connection() != 0:
			self.msg("Cannot connect to %s. Rebooting !!!" % self.ssh_ip)
			if self.reboot() != 0:
				return 1
		return 0

	def mcu_connect(self):
		self.mcu_console = Telnet(self.mcu_telnet_ip, self.mcu_telnet_port)

	def mcu_disconnect(self):
		self.mcu_console.close()

	def mcu_expect(self, string, timeout = None):
		self.mcu_console.expect(string, timeout)

	def mcu_send(self, string):
		self.mcu_console.send(string)

	def board_connect(self):
		self.board_console = Telnet(self.mcu_telnet_ip, self.mcu_board_telnet_port, self.board_log)

	def board_disconnect(self):
		self.board_console.close()

	def board_expect(self, string, timeout = None):
		self.board_console.expect(string, timeout)

	def board_send(self, string):
		self.board_console.send(string)

	def pdu_connect(self):
		self.pdu_console = SSH(self.pdu_ssh_ip, self.pdu_ssh_username, self.pdu_ssh_password)

	def pdu_disconnect(self):
		self.pdu_console.close()

	def pdu_expect(self, string, timeout = None):
		self.pdu_console.expect(string, timeout)

	def pdu_send(self, string):
		self.pdu_console.send(string)

	def bmc_connect(self):
		self.bmc_console = SSH(self.bmc_ssh_ip, self.bmc_ssh_username, self.bmc_ssh_password)

	def bmc_disconnect(self):
		self.bmc_console.close()

	def bmc_expect(self, string, timeout = None):
		self.bmc_console.expect(string, timeout)

	def bmc_send(self, string):
		self.bmc_console.send(string)

	def msg(self, msg):
		print(msg)

	def reboot(self):
		self.pdu_connect()
		self.msg("Connected to PDU console")
		self.pdu_send("power outlets %s off" % self.pdu_outlet)
		self.pdu_expect("y/n]")
		self.pdu_send("y")
		self.pdu_expect("#")
		self.msg("Issued Power Off from PDU, Waiting for 60 secs before powering on ...")
		time.sleep(60)
		self.pdu_send("power outlets %s cycle" % self.pdu_outlet)
		self.pdu_expect("y/n]")
		self.pdu_send("y")
		self.pdu_expect("#")
		self.msg("Issued Power Cycle from PDU")
		self.pdu_disconnect()
		self.msg("Disconnected from PDU console")

		if self.mcu_telnet_ip != "":
			self.msg("Waiting 30 seconds for MCU")
			time.sleep(30)
			self.mcu_connect()
			self.msg("Connected to MCU console")
			self.mcu_send("")
			self.mcu_expect("Hit 'P' key or toggle the power switch to turn the board on.")
			self.mcu_send("P")
			self.mcu_expect("MCU Command>")
			self.msg("Issued Board Reset from MCU")
			self.mcu_disconnect()
			self.msg("Disconnected from MCU console")
			self.board_connect()
			self.msg("Connected to Board console, waiting for board to boot ...")
			self.board_expect("login:", 600)
			self.msg("Board Booted !!")
			self.board_disconnect()
			self.msg("Disconnected from Board console")
			if self.test_connection() == 0:
				return 0
		else:
			# If BMC is available issue board reset via REST API
			if self.bmc_ssh_ip != "":
				self.test_connection(120, True)
				self.msg("BMC is alive")
				ep = "https://%s:%s@%s/xyz/openbmc_project/state/host0/attr/RequestedHostTransition" % (self.bmc_ssh_username, self.bmc_ssh_password, self.bmc_ssh_ip)
				state = "xyz.openbmc_project.State.Host.Transition.Off"
				os.system('curl -k -H "Content-Type: application/json" -d \'{"data": "%s"}\' -X PUT %s' % (state, ep))
				time.sleep(5)
				state = "xyz.openbmc_project.State.Host.Transition.On"
				os.system('curl -k -H "Content-Type: application/json" -d \'{"data": "%s"}\' -X PUT %s' % (state, ep))
				self.msg("Issued Host Reset via REST API")

			if self.test_connection(600) == 0:
				return 0

		return 1

	def test_connection(self, waittime = 30, bmc = False):
		ip = self.ssh_ip
		usr = self.ssh_username
		pwd = self.ssh_password
		tgt = "Board"

		if bmc:
			tgt = "BMC"
			ip = self.bmc_ssh_ip
			usr = self.bmc_ssh_username
			pwd = self.bmc_ssh_password

		self.msg("Waiting Max %d seconds for %s to boot" % (waittime, tgt))

		while waittime > 0:
			if self.test_ping(ip) == 0 and self.test_ssh(ip, usr, pwd) == 0:
				self.msg("%s:%s is Alive" % (tgt, ip))
				return 0
			time.sleep(10)
			waittime = waittime - 10
		return 1

	def test_ping(self, ip):
		if os.system("ping -c 1 " + ip) == 0:
			return 0
		return 1

	def test_ssh(self, ip, usr, pwd):
		conn = pexpect.spawn("%s %s@%s" % (os.environ.get('TARGET_SSH_CMD', 'ssh'), usr, ip))
		try:
			# Wait for prompt for 10 seconds
			if pwd:
				conn.expect("password:", 10)
			else:
				conn.expect("Last login:", 10)
		except:
			conn.close()
			return 1
		conn.close()
		return 0

board_config = {
	#       SSH IP            MCU_IP         PDU_IP          BMC_IP  PDU_OUTLET   NAME
	"10.28.34.128" : ["10.28.34.127", "10.28.6.169",             "",       "13",  "b7"],
	"10.28.34.130" : ["10.28.34.129", "10.28.6.169",             "",       "12",  "b8"],
	"10.28.34.132" : ["10.28.34.131", "10.28.6.169",             "",       "11",  "b9"],
	"10.28.34.134" : [            "", "10.28.6.173",             "",       "18", "b19"],
	"10.28.34.136" : [            "", "10.28.6.173",             "",       "19", "b20"],
	"10.28.34.137" : [            "", "10.28.6.174",   "10.28.35.5",        "3", "b27"],
	"10.28.34.138" : [            "", "10.28.6.174",   "10.28.35.4",        "4", "b28"],
	"10.28.34.139" : [            "", "10.28.6.175",  "10.28.35.21",       "11", "b32"],
	"10.28.34.140" : [            "", "10.28.6.175",  "10.28.35.19",        "9", "b33"],
}

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--ssh-ip", dest = 'ssh_ip', action = "store", required = True)
	parser.add_argument("--force-reboot", dest = 'force_reboot', action = "store_true",
				default = False, required = False)
	args = parser.parse_args()

	conf = board_config[args.ssh_ip]
	board = Board(args.ssh_ip, "ci", None, conf[0], "9760", "9761", conf[1], "admin",
		      "raritan0", conf[3], conf[2], "root", "0penBmc")

	if args.force_reboot:
		print("Force rebooting board")
		board.reboot()

	if board.setup() != 0:
		sys.exit('Board %s Setup Failed' % args.ssh_ip)
	print("%s is Alive !!!" % args.ssh_ip)


