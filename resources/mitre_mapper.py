#!/usr/bin/env python

import csv
import glob
import json
import csv
from copy import deepcopy
from pyhocon import ConfigFactory


def main():

	mitre_map = {
	"name": "Exabeam MITRE Map",
	"version": "4.2",
	"description": "Exabeam MITRE Map",
	"domain": "mitre-enterprise",
	"techniques": []
	}

	techniques = {}
	mitre_update_map = {}

	with open('mitre_map_fixed.csv', 'r') as f:
		reader = csv.reader(f)
		
		for row in reader:
		   k, v = row
		   mitre_update_map[k] = v

	for filename in glob.glob('../input_c1907/martini/config/default/rules_default.conf'):
		conf = ConfigFactory.parse_file(filename)
		for x in conf:
			for y in conf[x]:
				if not 'RuleLabels' in conf[x][y]:
					continue
				# print conf[x][y]
				if 'mitre' not in conf[x][y]['RuleLabels']:
					print "Nope", conf[x][y]['RuleName']
				else:
					for technique in conf[x][y]['RuleLabels']['mitre']:						
						my_technique = {"color": "#6dbb51"}
						my_main_technique = {}
						mitre_id = str(technique)
						# if mitre_id in mitre_update_map:
						# 	mitre_id = mitre_update_map[mitre_id]

						my_technique['techniqueID'] = mitre_id
						my_technique['comment'] = "{} - {}".format(y, conf[x][y]['RuleName'])
						if mitre_id in techniques:
							techniques[mitre_id]['comment'] += "\n\n" + my_technique['comment']
						else:
							techniques[mitre_id] = my_technique

						if '.' in mitre_id:
							my_main_technique = deepcopy(my_technique)
							mitre_id_main = mitre_id.split(".")[0]
							my_main_technique['techniqueID'] = mitre_id_main
							if mitre_id_main in techniques:
								techniques[mitre_id_main]['comment'] += "\n\n" + my_main_technique['comment']
							else:
								techniques[mitre_id_main] = my_main_technique

	for ttp in techniques:
		techniques[ttp]['comment'] = "{} rules".format(len(techniques[ttp]['comment'].split('\n\n')))

	mitre_map['techniques'] = techniques.values()

	with open('mitre_map.json', 'w') as outfile:
	    json.dump(mitre_map, outfile)

if __name__ == "__main__":
	main()
