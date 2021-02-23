#!/usr/bin/env python3

# A python based prolog interface for my program EABR, based on the pyswip module


# import modules
from pyswip import Prolog
from colorama import Fore, init, Style


class PYPROLOG:

	def __init__(self, query, prolog_file):	
		self.query_term = query
		self.prolog_code = prolog_file
		
		self.yellow = Fore.LIGHTYELLOW_EX
		self.reset = Fore.RESET
		self.red = Fore.RED
		self.green = Fore.LIGHTGREEN_EX
		self.blue = Fore.BLUE
		self.white = Fore.LIGHTWHITE_EX
		self.style = Style.BRIGHT



	def query_knowledge_base(self):
		prolog = Prolog()
		prolog.consult(self.prolog_code)
		return list(prolog.query(self.query_term))

		
	def print_query_result(self, query_result_list):
		print(f'\n[+] The query submitted is: {self.green}%s{self.reset}' % (self.query_term))
		
		if not query_result_list:
			print(f'\n[-] The result of your submitted query: {self.red}%s{self.reset}' % ('False'))
			raise SystemExit

		for query_result in query_result_list:
			
			if len(query_result) == 0:
				print(f'\n[+] The result of your submitted query: {self.green}%s{self.reset}' % ('True'))
				raise SystemExit

			
			#print(f'\n[+] The result of your submitted query: {Green}{query_result}{Reset}')
			query_result_1 = query_result['X']
			query_result_2 = query_result['D'][0]
			query_result_3 = query_result['D'][1]
			print(f'\n[+] The result of your submitted query: X is {self.green}{query_result_1}{self.reset}')
			print(f'\n[+] The result of your submitted query: D is {self.green}[{query_result_2},{query_result_3}]{self.reset}')
					
	
	def start(self):
		query_result_list = self.query_knowledge_base()
		self.print_query_result(query_result_list)
