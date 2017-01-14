#!/usr/bin/python
# ========================= #
# ASA Config Generator
# Version 0.1
# Author: Andreas Leon
# LinkedIn: https://linkedin.com/in/andreasleon
# ========================= #

# Imports
import sys

class Terminal:
	drawSingleLine = '-'*30
	drawDoubleLine = '='*30

class Main:
	def __init__(self,terminal):
		self.terminal = terminal

	def start(self):
		try:
			# Program goes here
			print(self.terminal.drawDoubleLine)
			print(' ASA Config Generator')
			print(' Version: 0.1')
			print(self.terminal.drawDoubleLine)

			hostName = raw_input('Enter name of firewall (example: fw1): ')
			domainName = raw_input('Enter clients domain name (example: contoso.com): ')
			firewallPassword = raw_input('Enter a password for the firewall: ')
			vpnKey = raw_input('Enter a password for VPN (Preshared Key): ')
			firewallIP = raw_input('Enter IP of firewall: ')
			localADInput = raw_input('Enter IP of AD server (if any, otherwise just press enter): ')
			userName = raw_input('Enter a username: ')
			passWord = raw_input('Enter a password for {}: '.format(userName))
			mailTo = raw_input('Enter a email to send critical warnings to: ')

			d1 = domainName.split('.')[0]
			domainStripped = d1.upper()
			configFile = '{}.{}.defaultconfig.txt'.format(hostName,domainName)

			t1 = firewallIP.split('.')[0]
			t2 = firewallIP.split('.')[1]
			t3 = firewallIP.split('.')[2]

			localNetwork = '{}.{}.{}.0'.format(t1,t2,t3)
			extendedNetwork = '{}.{}.0.0'.format(t1,t2)
			dhcpStart = '{}.{}.{}.30'.format(t1,t2,t3)
			dhcpStop = '{}.{}.{}.250'.format(t1,t2,t3)

			if(t3 != '100'):
				vpnNetwork = '{}.{}.100.0'.format(t1,t2)
				vpnNetworkStart ='{}.{}.100.10'.format(t1,t2)
				vpnNetworkEnd = '{}.{}.100.50'.format(t1,t2)
			else:
				vpnNetwork ='{}.{}.200.0'.format(t1,t2)
				vpnNetworkStart ='{}.{}.200.10'.format(t1,t2)
				vpnNetworkEnd = '{}.{}.200.50'.format(t1,t2)

			defaultNetMask = '255.255.255.0'
			extendedNetMask = '255.255.0.0'

			if(localADInput != ''):
				localAD = localADInput
			else:
				localAD = '8.8.8.8'

			with open(configFile, 'w') as config:
				config.write('configure factory-default {}\n'.format(firewallIP))
				config.write('hostname {}\n'.format(hostName))
				config.write('domain-name {}\n'.format(domainName))
				config.write('enable password {}\n'.format(firewallPassword))
				config.write('passwd {}\n'.format(firewallPassword))
				config.write('ftp mode passive\n')
				config.write('clock timezone CEST 1\n')
				config.write('clock summer-time CEDT recurring last Sun Mar 2:00 last Sun Oct 3:00\n')
				config.write('dns server-group DefaultDNS\n')
				config.write(' domain-name {}\n'.format(domainName))
				config.write('access-list outside_access_in extended permit icmp any {} {} echo-reply\n'.format(extendedNetwork,extendedNetMask))
				config.write('access-list outside_access_in extended permit icmp any any source-quench\n')
				config.write('access-list outside_access_in extended permit icmp any any unreachable\n')
				config.write('access-list outside_access_in extended permit icmp any any time-exceeded\n')
				config.write('access-list outside_access_in extended permit icmp any interface outside\n')
				config.write('access-list outside_access_in extended permit udp any any eq isakmp\n')
				config.write('access-list outside_access_in extended permit udp any any eq 4500\n')
				config.write('access-list outside_access_in extended permit esp any any\n')
				config.write('access-list local_LAN_access standard permit host 0.0.0.0\n')
				config.write('access-list inside_nat0_outbound extended permit ip any {} {}\n'.format(extendedNetwork,extendedNetMask))
				config.write('access-list outside_1_cryptomap extended permit ip {} {} {} {}\n'.format(localNetwork,defaultNetMask,vpnNetwork,defaultNetMask))
				config.write('access-list SplitTunnelAcl standard permit any\n')
				config.write('pager lines 24\n')
				config.write('logging enable\n')
				config.write('logging asdm informational\n')
				config.write('logging mail errors\n')
				config.write('logging from-address {}@{}\n'.format(hostName,domainName))
				config.write('logging recipient-address {} level critical\n'.format(mailTo))
				config.write('mtu inside 1500\n')
				config.write('mtu outside 1500\n')
				config.write('ip local pool vpnclients {}-{} mask {}\n'.format(vpnNetworkStart,vpnNetworkEnd,defaultNetMask))
				config.write('icmp unreachable rate-limit 1 burst-size 1\n')
				config.write('no asdm history enable\n')
				config.write('arp timeout 14400\n')
				config.write('global (outside) 1 interface\n')
				config.write('nat (inside) 0 access-list inside_nat0_outbound\n')
				config.write('nat (inside) 1 0.0.0.0 0.0.0.0\n')
				config.write('access-group outside_access_in in interface outside\n')
				config.write('timeout xlate 3:00:00\n')
				config.write('timeout conn 1:00:00 half-closed 0:10:00 udp 0:02:00 icmp 0:00:02\n')
				config.write('timeout sunrpc 0:10:00 h323 0:05:00 h225 1:00:00 mgcp 0:05:00 mgcp-pat 0:05:00\n')
				config.write('timeout sip 0:30:00 sip_media 0:02:00 sip-invite 0:03:00 sip-disconnect 0:02:00\n')
				config.write('timeout sip-provisional-media 0:02:00 uauth 0:05:00 absolute\n')
				config.write('timeout tcp-proxy-reassembly 0:01:00\n')
				config.write('dynamic-access-policy-record DfltAccessPolicy\n')
				config.write('http server enable\n')
				config.write('http {} {} inside\n'.format(localNetwork,defaultNetMask))
				config.write('http {} {} inside\n'.format(vpnNetwork,defaultNetMask))
				config.write('no snmp-server location\n')
				config.write('no snmp-server contact\n')
				config.write('snmp-server enable traps snmp authentication linkup linkdown coldstart\n')
				config.write('crypto ipsec transform-set ESP-3DES-MD5 esp-des esp-md5-hmac\n')
				config.write('crypto ipsec security-association lifetime seconds 28800\n')
				config.write('crypto ipsec security-association lifetime kilobytes 4608000\n')
				config.write('crypto dynamic-map outside_dyn_map 20 set pfs\n')
				config.write('crypto dynamic-map outside_dyn_map 20 set transform-set ESP-3DES-MD5\n')
				config.write('crypto map outside_map 20 match address outside_1_cryptomap\n')
				config.write('crypto map outside_map 20 set pfs\n')
				config.write('crypto map outside_map 20 set transform-set ESP-3DES-MD5\n')
				config.write('crypto map outside_map 65535 ipsec-isakmp dynamic outside_dyn_map\n')
				config.write('crypto map outside_map interface outside\n')
				config.write('crypto isakmp enable outside\n')
				config.write('crypto isakmp policy 10\n')
				config.write(' authentication pre-share\n')
				config.write(' encryption 3des\n')
				config.write(' hash md5\n')
				config.write(' group 2\n')
				config.write(' lifetime 86400\n')
				config.write('crypto isakmp policy 30\n')
				config.write(' authentication pre-share\n')
				config.write(' encryption 3des\n')
				config.write(' hash sha\n')
				config.write(' group 1\n')
				config.write(' lifetime 86400\n')
				config.write('telnet {} {} inside\n'.format(localNetwork,defaultNetMask))
				config.write('telnet {} {} inside\n'.format(vpnNetwork,defaultNetMask))
				config.write('ssh timeout 5\n')
				config.write('console timeout 0\n')
				config.write('management-access inside\n')
				config.write('dhcpd address {}-{} inside\n'.format(dhcpStart,dhcpStop))
				config.write('dhcpd dns {} interface inside\n'.format(localAD))
				config.write('dhcpd wins {} interface inside\n'.format(localAD))
				config.write('dhcpd lease 7200 interface inside\n')
				config.write('dhcpd domain {} interface inside\n'.format(domainName))
				config.write('dhcpd enable inside\n')
				config.write('!\n')
				config.write('threat-detection basic-threat\n')
				config.write('threat-detection statistics port\n')
				config.write('threat-detection statistics protocol\n')
				config.write('threat-detection statistics access-list\n')
				config.write('threat-detection statistics tcp-intercept rate-interval 30 burst-rate 400 average-rate 200\n')
				config.write('ntp server 129.6.15.28 source outside prefer\n')
				config.write('webvpn\n')
				config.write('group-policy {} internal\n'.format(domainStripped))
				config.write('group-policy {} attributes\n'.format(domainStripped))
				config.write(' dns-server value {}\n'.format(localAD))
				config.write(' vpn-tunnel-protocol IPSec\n')
				config.write(' split-tunnel-policy tunnelspecified\n')
				config.write(' split-tunnel-network-list value SplitTunnelAcl\n')
				config.write(' default-domain value {}\n'.format(domainName))
				config.write('username {} password {}\n'.format(userName,passWord))
				config.write('username {} attributes\n'.format(userName))
				config.write(' vpn-group-policy {}\n'.format(domainStripped))
				config.write('tunnel-group {} type remote-access\n'.format(domainStripped))
				config.write('tunnel-group {} general-attributes\n'.format(domainStripped))
				config.write(' address-pool vpnclients')
				config.write(' default-group-policy {}\n'.format(domainStripped))
				config.write('tunnel-group {} ipsec-attributes\n'.format(domainStripped))
				config.write(' pre-shared-key {}\n'.format(vpnKey))
				config.write('!\n')
				config.write('class-map inspection_default\n')
				config.write(' match default-inspection-traffic\n')
				config.write('!\n')
				config.write('!\n')
				config.write('policy-map type inspect dns preset_dns_map\n')
				config.write(' parameters\n')
				config.write('  message-length maximum 512\n')
				config.write('policy-map global_policy\n')
				config.write(' class inspection_default\n')
				config.write('  inspect dns preset_dns_map\n')
				config.write('  inspect ftp\n')
				config.write('  inspect h323 h225\n')
				config.write('  inspect h323 ras\n')
				config.write('  inspect rsh\n')
				config.write('  inspect rtsp\n')
				config.write('  inspect sqlnet\n')
				config.write('  inspect skinny \n')
				config.write('  inspect sunrpc\n')
				config.write('  inspect xdmcp\n')
				config.write('  inspect sip\n')
				config.write('  inspect netbios\n')
				config.write('  inspect tftp\n')
				config.write('!\n')
				config.write('service-policy global_policy global\n')
				config.write('!\n')
				config.write('write mem\n')
				config.write('!\n')
				config.write('reload noconfirm')

		except KeyboardInterrupt:
			print('\nExititng...')
			sys.exit(1)

if __name__ == ('__main__'):
		terminal = Terminal()
		main = Main(terminal)
		main.start()