from faker import Faker
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp
from os import system, geteuid
from threading import Thread
import sys
import colorama
from time import sleep
from random import choice
from string import ascii_letters


colorama.init(autoreset=True)


logo = f"""
[!!]The author is not responsible for your actions 

{colorama.Fore.LIGHTGREEN_EX}`7MMF'     A     `7MF'`7MMF'{colorama.Fore.RED}`7MM\"\"\"YMM          `7MM               
{colorama.Fore.LIGHTGREEN_EX}  `MA     ,MA     ,V    MM  {colorama.Fore.RED}  MM    `7            MM               
{colorama.Fore.LIGHTGREEN_EX}   VM:   ,VVM:   ,V     MM  {colorama.Fore.RED}  MM   d    ,6"Yb.    MM  ,MP' .gP\"Ya  
{colorama.Fore.LIGHTGREEN_EX}    MM.  M' MM.  M'     MM  {colorama.Fore.RED}  MM""MM   8)   MM    MM ;Y   ,M'   Yb 
{colorama.Fore.LIGHTGREEN_EX}    `MM A'  `MM A'      MM  {colorama.Fore.RED}  MM   Y    ,pm9MM    MM;Mm   8M\"\"\"\"\"\" 
{colorama.Fore.LIGHTGREEN_EX}     :MM;    :MM;       MM  {colorama.Fore.RED}  MM       8M   MM    MM `Mb. YM.    , 
{colorama.Fore.LIGHTGREEN_EX}      VF      VF      .JMML.{colorama.Fore.RED}.JMML.     `Moo9^Yo..JMML. YA. `Mbmmd' 
{colorama.Fore.LIGHTGREEN_EX}
	{colorama.Fore.LIGHTBLUE_EX}MADE BY XSARZ     [https://linktr.ee/xsarz]
"""

help_msg = f"""
----------------------
{colorama.Fore.RED}[!!] The adapter must be in monitoring mode. Not every adapter will work{colorama.Fore.RESET}
help flags: -h, --h, -help --help

Flags:

-i: interface flag (wifi adapter name) [wlan0mon, wlan1mon, ect]
-c: Number of networks to create (1 by default)
-wn: Name for networks (random by default)

Startup examples:
  #~ wifake.py -i wlan0mon -c 10
  #~ wifake.py -i wlan0mon -wn sucker
  #~ wifake.py -i wlan0mon -c 10 -wn idiot
  #~ wifake.py -i wlan0mon
----------------------
"""

flags = [
	"-wn",
	"-i", 
	"-c", 
	"-h", '--h', '--help', '-help'
	
]


class FAKE_WIFI:
	total_ssids: int = 1
	network_names: str = None
	iface: str = None

	def generate_random_string(self, length: int = 5):
		return ''.join(choice(ascii_letters) for _ in range(length))



	def create_fake_data(self, count: int = 1, network_name: str = None) -> list:
		"""
		Create fake name for SSID and mac address

		count: number for fake AP's
		network_name: name for network (SSID) (optional)
	
		"""
		faker = Faker()
		fake_data = [(network_name+'-'+self.generate_random_string() or faker.domain_word(), faker.mac_address()) for i in range(int(count))]
		return fake_data

	def send_wifi_beacon(self, wifi_ssid: str, mac: str, iface: str, loop: int = 1, inter: float = 0.1, verbose: int = 0):
		"""
		Separate thread for each AP

		wifi_ssid: name of SSID (network)
		mac: network mac address
		iface: interface in monitor mode
		"""

		print(f"Name: {colorama.Fore.LIGHTYELLOW_EX}{wifi_ssid}{colorama.Fore.RESET} - [mac: {colorama.Fore.LIGHTBLUE_EX}{mac}{colorama.Fore.RESET}]")
		dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
		beacon = Dot11Beacon(cap="ESS+privacy")
		essid = Dot11Elt(ID="SSID", info=wifi_ssid, len=len(wifi_ssid))
		frame = RadioTap()/dot11/beacon/essid
		try:sendp(frame, inter=inter, loop=loop, iface=iface, verbose=verbose)
		except Exception as e:
			print(f'{colorama.Fore.RED}[{mac} - {wifi_ssid}] -> Error: {e}')

	def arg_parse(self, args: list) -> list:
		if len(args) == 1:
			print(help_msg)
			exit()


		original_list = args[1:]

		if original_list[0] in ["-h", '--h', '--help', '-help'] and len(original_list) == 1:
			print(help_msg)
			exit()

		result_list = []
		seen_flags = set()
		current_flag = None
		for item in original_list:
			if item.startswith('-'):
				if item in seen_flags:
					print(f"{colorama.Fore.RED}[!!]Same flags:", item)
					exit()
				seen_flags.add(item)
				current_flag = item
			else:
				if current_flag not in flags:
					print(f"{colorama.Fore.RED}[!!]Invalid flag [{current_flag}]")
					exit()
				result_list.append({'flag': current_flag, 'value': item})
				current_flag = None
		return result_list

	def sort_args(self, args: list):
		for i in args:
			flag = i["flag"]
			value = i['value']
			if flag == '-i':self.iface = value
			if flag == '-wn': self.network_names = value
			try:
				if flag == '-c': self.total_ssids = int(value)
			except ValueError:
				print(f'{colorama.Fore.RED}[!!]Quantity indicated incorrectly')
				exit()
		if self.iface is None:
			print(f'{colorama.Fore.RED}[!!]The required argument "-i" is missing.\nUse --help')
			exit()

	def run(self):
		system("clear || cls")
		print(logo)
		if geteuid() != 0:
			print(f"{colorama.Fore.RED}[!!]Start it as root.")
			exit()
		self.sort_args(self.arg_parse(sys.argv))
		print(f"Interface: {colorama.Fore.GREEN}{self.iface}{colorama.Fore.RESET}\nAccess points: {colorama.Fore.GREEN}{self.total_ssids}{colorama.Fore.RESET}\nName for points: {colorama.Fore.LIGHTYELLOW_EX}{self.network_names or 'random'}")
		input("\nPress any key to continue")
		fake_ssids = self.create_fake_data(self.total_ssids, self.network_names)
		print(f'{colorama.Fore.LIGHTBLUE_EX}[{colorama.Fore.GREEN}*{colorama.Fore.LIGHTBLUE_EX}]{colorama.Fore.YELLOW}Starting... [CTRL + c to stop]')
		for ssid, mac in fake_ssids:
			Thread(target=self.send_wifi_beacon, args=(ssid, mac, self.iface)).start()
			sleep(0.2)
		


if __name__ == "__main__":
	FAKE_WIFI().run()
	