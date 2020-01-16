#!/usr/local/bin/python3
# coding: utf-8

# Import modules
from os import path
from urllib import request
from json import loads as json_loads
from hashlib import md5
from terminaltables import AsciiTable
from colorama import Fore
from webbrowser import open as webbrowser_open

# Logo
logo = (Fore.MAGENTA + r'''
  
  █▀█ █░█ ▄▀█ █▄░█ ▀█▀ █▀█ █▀▄▀█   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
  █▀▀ █▀█ █▀█ █░▀█ ░█░ █▄█ █░▀░█   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄
                               Created by LimerBoy with ''' + Fore.RED + '''Love <3 ''' + Fore.MAGENTA + '''

   * You must select the path to the file.
   * Only the hash of the file on Virustotal will be checked.
   * The file itself will not be sent.

	''' + Fore.RESET)

# Main
def main():

	# Get file hash
	def getFilemd5(filename):
	    hash_md5 = md5()
	    with open(filename, "rb") as f:
	        for chunk in iter(lambda: f.read(4096), b""):
	            hash_md5.update(chunk)
	    return hash_md5.hexdigest()

	# Select file
	file = input(Fore.CYAN + ' >>> Select file: ' + Fore.RESET)
	if not path.exists(file):
		exit(Fore.RED + "[!] File " + file + " not found!" + Fore.RESET)
	else:
		file_md5 = getFilemd5(file)

	# Get VirusTotal results
	virustotal = json_loads(request.urlopen('https://www.virustotal.com/ui/search?query=' + file_md5).read())

	# Show scanners results in table
	detection = virustotal['data'][0]['attributes']['last_analysis_results']
	table_data = [
	    ['Scanner', 'Category']
	]
	for res in detection:
		engine   = detection[res]['engine_name']
		category = detection[res]['category']

		# Change color if file malicious
		if category.lower() == "undetected":
			category = Fore.GREEN + category
		else:
			category = Fore.RED + category

		category += Fore.RESET
		# Add to table
		table_data.append([engine, category])

	# Table
	table = AsciiTable(table_data)
	print(table.table)

	# Show stats
	detection = virustotal['data'][0]['attributes']['last_analysis_stats']
	print(
		"\n>> STATS:"
		"\n-*  Malicious   : " + str(detection['malicious'])  +
		"\n-*  Suspicious  : " + str(detection['suspicious']) +
		"\n-*  Harmless    : " + str(detection['harmless'])   +
		"\n-*  Undetected  : " + str(detection['undetected'])
		)

	# Open full report?
	if virustotal['data']:
		if input('\n [?] Open full VirusTotal report? (y/n)\n ---> ').lower() in ('y', 'yes'):
			webbrowser_open('https://www.virustotal.com/gui/file/' + file_md5 + '/detection')

if __name__ == '__main__':
	print(logo)
	main()