# Enhanced Argumentation Based Reasoner (EABR)

#!/usr/bin/env python3

# A user interface to ABR

'''
To test or execute the model, we can use the enter the query
prove([neg(isCulprit(X))], D) and prove([(isCulprit(X))], D)
'''

try:
	# import modules
	import argparse
	from colorama import Fore, init, Style
	from pyswip import Prolog
except KeyboardInterrupt:
    print('[!] Detected CTRL + C ...Now exiting!')
    raise SystemExit
except:
    print('[!] Missing requirements. Try running python3 -m pip install -r requirements.txt')
    raise SystemExit

init()

Yellow = Fore.LIGHTYELLOW_EX
Reset = Fore.RESET
Red = Fore.RED
Green = Fore.LIGHTGREEN_EX
Blue = Fore.BLUE
White = Fore.LIGHTWHITE_EX
Style = Style.BRIGHT


def display_banner():
	
	banner_text = '''

 .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. |
| |      __      | || |   ______     | || |  _______     | |
| |     /  \     | || |  |_   _ \    | || | |_   __ \    | |
| |    / /\ \    | || |    | |_) |   | || |   | |__) |   | |
| |   / ____ \   | || |    |  __'.   | || |   |  __ /    | |
| | _/ /    \ \_ | || |   _| |__) |  | || |  _| |  \ \_  | |
| ||____|  |____|| || |  |_______/   | || | |____| |___| | |
| |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------' 

Argumentation Based Reasoner.
Performs cyber attack attribution using argumentation with abduction.

By Faisal Gama
Contact: info@faisalgama.com
Github: github.com/alifa2try/argumentation-based-reasoner
Website: faisalgama.com 
	'''
	print(f"{Yellow}{Style}{banner_text}{White}")


def get_argument():
	parser = argparse.ArgumentParser(description=display_banner())
	parser.add_argument("-q", "--query", dest= "query", help="Query")
	option = parser.parse_args()

	if not option.query:
		parser.error(f"{Red}[-] You need to specify query, enter -h for help")
		raise SystemExit	
	return option.query	


def query_knowledge_base(query_term):
	prolog = Prolog()
	prolog.consult('code.pl')
	return list(prolog.query(query_term))

	
def print_query_result(query_term, query_result_list):
	print(f'[+] The query submitted is: {Green}%s{Reset}' % (query_term))
	
	if not query_result_list:
		print(f'\n[-] The result of your submitted query: {Red}%s{Reset}' % ('False'))
		raise SystemExit

	for query_result in query_result_list:
		
		if len(query_result) == 0:
			print(f'\n[+] The result of your submitted query: {Green}%s{Reset}' % ('True'))
			raise SystemExit

		
		#print(f'\n[+] The result of your submitted query: {Green}{query_result}{Reset}')
		query_result_1 = query_result['X']
		query_result_2 = query_result['D'][0]
		query_result_3 = query_result['D'][1]
		print(f'\n[+] The result of your submitted query: X is {Green}{query_result_1}{Reset}')
		print(f'\n[+] The result of your submitted query: D is {Green}[{query_result_2},{query_result_3}]{Reset}')
				
		'''

		for key, value in query_result.items():
			if 'Atom' in value:
				value = list(value)
				print(f'\n[+] The result of your submitted query: {key} is {value}')

			print(f'\n[+] The result of your submitted query: {key} is {value}')

		'''	

		

		#print('\n[+] The result of your submitted query: ', query_result['X'])


query_term = get_argument()
query_result_list = query_knowledge_base(query_term)
print_query_result(query_term, query_result_list)
