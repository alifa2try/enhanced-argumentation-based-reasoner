#!/usr/bin/env python3


# Enhanced Argumentation Based Reasoner (EABR)

'''
To test or execute the model, we can use the enter the query:
prove([neg(isCulprit(X))], D) OR prove([(isCulprit(X))], D)
'''


# import modules
try:
	import argparse
	from colorama import Fore, init, Style
	import pyprolog

except KeyboardInterrupt:
    print('[!] Detected CTRL + C ...Now exiting!')
    raise SystemExit

except:
    print('[!] Missing requirements. Try running python3 -m pip install -r requirements.txt')
    raise SystemExit


class EABR:

	def __init__(self):

		self.yellow = Fore.LIGHTYELLOW_EX
		self.reset = Fore.RESET
		self.red = Fore.RED
		self.green = Fore.LIGHTGREEN_EX
		self.blue = Fore.BLUE
		self.white = Fore.LIGHTWHITE_EX
		self.my_Style = Style.BRIGHT


	def display_banner(self):
			
			banner_text = '''


		oooooooooooo               .o.       oooooooooo.  ooooooooo.   
		`888'     `8              .888.      `888'   `Y8b `888   `Y88. 
		 888                     .8"888.      888     888  888   .d88' 
		 888oooo8               .8' `888.     888oooo888'  888ooo88P'  
		 888    "    8888888   .88ooo8888.    888    `88b  888`88b.    
		 888       o          .8'     `888.   888    .88P  888  `88b.  
		o888ooooood8         o88o     o8888o o888bood8P'  o888o  o888o 
				v1.0.0

		Enhanced Argumentation Based Reasoner
		Performs Cyber Attack Attribution using argumentation and abductive reasoning

		By Faisal Gama
		Contact: info@faisalgama.com
		Github: github.com/alifa2try/mail-hunter
		Website: faisalgama.com 
			'''
			print(f"{self.yellow}{self.my_Style}{banner_text}{self.white}")


	def get_argument(self):
		parser = argparse.ArgumentParser(description=self.display_banner())
		parser.add_argument("-q", "--query", dest= "query", help="Query")
		parser.add_argument("-pl", "--prolog_file", dest= "prolog_file", help="Prolog File")
		option = parser.parse_args()

		if not option.query:
			parser.error(f"{self.red}[-] You need to specify query, enter -h for help")
			raise SystemExit
		elif not option.prolog_file:
			parser.error(f"{self.red}[-] You need to specify a prolog file, enter -h for help")
			raise SystemExit		
		return option	


	def run(self):
		option = self.get_argument() 
		query = option.query
		prolog_file = option.prolog_file
		prolog_interface = pyprolog.PYPROLOG(query, prolog_file)
		prolog_interface.start()


eabr = EABR()
eabr.run() 	