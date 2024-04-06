from scapy.layers.dot11 import Dot11, sniff
from os import system, geteuid
import sys
import colorama
colorama.init(autoreset=True)

import subprocess


logo = f"""
[!!]The author is not responsible for your actions 


{colorama.Fore.LIGHTGREEN_EX}`7MMF'     A     `7MF\'`7MMF'{colorama.Fore.RED} .M\"\"\"bgd                                           
{colorama.Fore.LIGHTGREEN_EX}  `MA     ,MA     ,V    MM  {colorama.Fore.RED},MI    "Y                                           
{colorama.Fore.LIGHTGREEN_EX}   VM:   ,VVM:   ,V     MM  {colorama.Fore.RED}`MMb.      ,p6"bo   ,6"Yb.  `7MMpMMMb.  `7MMpMMMb.  
{colorama.Fore.LIGHTGREEN_EX}    MM.  M' MM.  M'     MM  {colorama.Fore.RED}  `YMMNq. 6M'  OO  8)   MM    MM    MM    MM    MM  
{colorama.Fore.LIGHTGREEN_EX}    `MM A'  `MM A'      MM  {colorama.Fore.RED}.     `MM 8M        ,pm9MM    MM    MM    MM    MM  
{colorama.Fore.LIGHTGREEN_EX}     :MM;    :MM;       MM  {colorama.Fore.RED}Mb     dM YM.    , 8M   MM    MM    MM    MM    MM  
{colorama.Fore.LIGHTGREEN_EX}      VF      VF      .JMML.{colorama.Fore.RED}P"Ybmmd"   YMbmd'  `Moo9^Yo..JMML  JMML..JMML  JMML.
																				
	{colorama.Fore.LIGHTBLUE_EX}MADE BY XSARZ     [https://linktr.ee/xsarz]
"""

help_msg = f"""
----------------------
help flags: -h, --h, -help --help

Flags:
	Modes:
		-n: Show information about the network around
		-uc: Information about who is connected to the network
		-m: Traffic View Mode

	Params:
		mode [-uc]:
			wifi interface in monitor mode, mac address, timeout(optional, default: 30)

			examples:
				python WIScann.py -uc wlan0mon 00:1A:2B:3C:4D:5E 60
				python WIScann.py -uc wlan0mon 00:1A:2B:3C:4D:5E

		mode [-m]:
			wifi interface in monitor mode, wifi mac address (optional, default: All access points)

			examples:
				python WIScann.py -m wlan0mon 00:1A:2B:3C:4D:5E
				python WIScann.py -m wlan0mon
	----------------------
"""


class Scanner:

	
	def scan_wifi_networks(self):

		try:
			print(f"{colorama.Fore.GREEN}Scanning, please wait")
			if sys.platform.startswith('win'):
				result = subprocess.check_output(['netsh', 'wlan', 'show', 'network'])
			elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
				result = subprocess.check_output(['iwlist', 'scan'])
			else:
				print(f"{colorama.Fore.RED}[!]Unsupported platform")
				return
		
		
			return result.decode('utf-8')
		except subprocess.CalledProcessError as e:
			print(f"{colorama.Fore.RED}[!]Error: Unable to scan Wi-Fi networks. {e}")
			return None
		except Exception as e:
			print(f"{colorama.Fore.RED}[!]Error: {e}")
			return None


	def sniff_ap_users(self, ap_mac: str, iface: str, timeout: int = 15):
		users = set()

		def packet_callback(packet):
			if packet.haslayer(Dot11) and packet.addr2:
				if packet.addr3 == ap_mac.lower():
					if packet.addr2 not in users:
						print(f"{colorama.Fore.GREEN}User detected: {packet.addr2}")
					users.add(packet.addr2)
		print(f"{colorama.Fore.GREEN}Please wait...")
		try:sniff(prn=packet_callback, iface=iface, store=0, timeout=timeout)
		except Exception as e:
			print(f"{colorama.Fore.RED}[!]Error: {e}")
			exit()
		return users


	def show_networks_around(self):
		results = self.scan_wifi_networks()
		if results is None: return
		networks = self.result_parser(results)
		for iface in networks:
			print(f"\n=======================\nInterface: {colorama.Fore.GREEN}{iface['iface']}")
			for network in iface.get("results", []):
				print(f"\nId: {network.get('id')}\nName: {network.get('ESSID')}\nMAC: {network.get('MAC')}\nEncryption key: {network.get('e_key')}\nFrequency: {network.get('frequency')}\nChannel: {network.get('channel')}\nSignal: {network.get('signal_level')}\nLast beacon: {network.get('last_beacon')}\nSecure: {network.get('Secure')}")
				print("-------------------------")


	def show_connected_users(self, iface: str, mac: str, timeout: int = 15):
		print(f"{colorama.Fore.LIGHTCYAN_EX}Interface: {colorama.Fore.GREEN}{iface}{colorama.Fore.LIGHTCYAN_EX}\nTarget MAC: {colorama.Fore.GREEN}{mac}{colorama.Fore.LIGHTCYAN_EX}\nTimeout: {colorama.Fore.GREEN}{timeout}\n")
		users = self.sniff_ap_users(iface=iface, ap_mac=mac, timeout=timeout)
		print(f"---------------\n{colorama.Fore.LIGHTGREEN_EX}Total users detected: {colorama.Fore.BLUE}{len(users)}")
		for i in users:
			print(i)
		


	def sniff_wifi_network(self, iface: str, mac: str = None):
		def packet_callback(packet):
			if packet.haslayer(Dot11):
				if mac is None or packet.addr3 == mac.lower():
					print(f"{colorama.Fore.GREEN}Packet detected: {packet.summary()}")
					#packet.show()

		print(f"{colorama.Fore.GREEN}Start scanning.... [CTRL + C to QUIT]")
		try:
			sniff(prn=packet_callback, iface=iface, store=0, timeout=None)
		except Exception as e:
			print(f"{colorama.Fore.RED}[!]Error: {e}")

	def monitoring_mode(self, iface: str, mac: str = None):
		print(f"{colorama.Fore.LIGHTCYAN_EX}Interface: {colorama.Fore.GREEN}{iface}{colorama.Fore.LIGHTCYAN_EX}\nTarget MAC: {colorama.Fore.GREEN}{mac or 'All access points'}{colorama.Fore.LIGHTCYAN_EX}\n")
		print(f"{colorama.Fore.RED}[!]Specify the correct data and adapter in monitor mode, otherwise nothing will happen")
		self.sniff_wifi_network(iface=iface, mac=mac)



	def result_parser(self, text) -> list:
		networks = list()
		source = text.split("\n\n")
		source.remove("")
		for iface_result in source:
			if iface_result == '':continue
			info = {}
			res = "\n".join(iface_result.split("\n")[1:]).split("Cell")
			info["iface"] = iface_result.split("\n")[0].split(" ")[0]
			info["results"] = list()
			for net in res:
				temp = {}
				if net in (None, "", " "*10):continue
				id = net.split("\n")[0].split("-")[0].replace(" ", '')
				temp["id"] = id
				for e in net.split("\n"):
					if "ESSID" in e:
						temp["ESSID"] = e.split("ESSID")[-1][1:]
					if "Channel" in e:
						temp["channel"] = e.split("Channel")[-1][1:]
					if "Frequency" in e:
						temp["frequency"] = e.split("Frequency")[-1][1:]
					if "Signal level" in e:
						temp["signal_level"] = e.split("Signal level")[-1][1:]
					if "Last beacon:" in e:
						temp["last_beacon"] = e.split("Last beacon:")[-1][1:]
					if "Encryption key" in e:
						temp["e_key"] = e.split("Encryption key:")[-1]
					if "IEEE" in e:
						temp["Secure"] = e.split("IEEE")[-1][1:]
					if "Address" in e:
						temp["MAC"] = e.split("Address")[-1][1:]
				info["results"].append(temp)
			networks.append(info)
		return networks





	def arg_parse(self, args: list) -> list:
		if len(args) == 1:
			print(help_msg)
			exit()


		l = args[1:]

		if l[0] in ["-h", '--h', '--help', '-help'] and len(l) == 1:
			print(help_msg)
			exit()
		if l[0] == '-n':
			self.show_networks_around()
		elif l[0] == '-uc':
			try:t=int(l[3])
			except IndexError: t=30
			except ValueError:
				print(f"{colorama.Fore.RED}[!]Incorrect timeout value.")
				exit()
			try:self.show_connected_users(iface=l[1], mac=l[2], timeout=t)
			except IndexError:
				print(f"{colorama.Fore.RED}[!]Incorrect args. Type -h")
		elif l[0] == '-m':
			try:m=l[2]
			except IndexError: m=None
			try:self.monitoring_mode(iface=l[1], mac=m)
			except IndexError:
				print(f"{colorama.Fore.RED}[!]Incorrect args. Type -h")
		else:
			print(help_msg)
			exit()


	def run(self):
		system("clear || cls")
		print(logo)
		if geteuid() != 0:
			print(f"{colorama.Fore.RED}[!!]Start it as root.")
			exit()
		self.arg_parse(sys.argv)



if __name__ == "__main__":
	Scanner().run()
	
