#!/usr/bin/env python3

# NessusParse v1.0
# By Ryan Roth

"""
Usage:  NessusParse [options] (host | criticality) INFILE [OUTFILE]
        NessusParse (-h | --help)
        NessusParse (-v | --version)

Required Options:
    host               Output file sorted by host
    criticality        Output file sorted by criticality

Options:
    -d, --desc         Include description of the finding
    -h, --help         Show this screen and exit
    -v, --version      Print the NessusParse version
"""

import socket, os, sys
import xlsxwriter
from docopt import docopt
from bs4 import BeautifulSoup

is_windows = sys.platform.startswith('win')

# Console Colors
if is_windows:
    # Windows deserves coloring too :D
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
    try:
        import win_unicode_console , colorama
        win_unicode_console.enable()
        colorama.init()
        #Now the unicode will work ^_^
    except:
        print("[!] Error: Coloring libraries not installed, no coloring will be used.")
        G = Y = B = R = W = G = Y = B = R = W = ''


else:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white

def banner():
    print(r"""%s
     __                           ___
  /\ \ \___  ___ ___ _   _ ___   / _ \__ _ _ __ ___  ___
 /  \/ / _ \/ __/ __| | | / __| / /_)/ _` | '__/ __|/ _ \
/ /\  /  __/\__ \__ \ |_| \__ \/ ___/ (_| | |  \__ \  __/
\_\ \/ \___||___/___/\__,_|___/\/    \__,_|_|  |___/\___|
                                                      %s
                # Coded By @f1rstm4tter%s
    """ % (B,G,W))

criticality_dict = {1: 'Low',
                    2: 'Moderate',
                    3: 'High',
                    4: 'Critical'}

# Making soup out of the XML
def soup_nessus(input):
  try:
    infile = open(args['INFILE'],"r")
    contents = infile.read()
    soup = BeautifulSoup(contents,'xml')
    return soup
  except OSError as errorCode:
    print("%sError: "% (R) + str(errorCode))
  pass

def compile_findings(soup, compile_type, desc):
  findings = []
  reporthosts = soup.find_all('ReportHost')
  for i in reporthosts:
    reportitem = i.findChildren("ReportItem",recursive=True)
    for item in reportitem:
      if int(item.get('severity')) > 0:
        criticality = criticality_dict[int(item.get('severity'))]
        if compile_type and desc:
          finding = [i.get('name'), criticality, item.get('pluginName'), item.findChild("description", recursive=False).get_text()]
        elif compile_type and not desc:
          finding = [i.get('name'), criticality, item.get('pluginName')]
        elif not compile_type and desc:
          finding = [criticality, i.get('name'), item.get('pluginName'), item.findChild("description", recursive=False).get_text()]
        elif not compile_type and not desc:
          finding = [criticality, i.get('name'), item.get('pluginName')]
        findings.append(finding)
  if compile_type:
    return sorted(findings, key=lambda item: socket.inet_aton(item[0]))
  else:
    return sorted(findings, reverse=True)

def create_xlsx(findings, outfile, compile_type, desc):
  print("%s[-] Writing output to file: %s%s%s%s" % (Y, W, B, outfile, W))
  workbook = xlsxwriter.Workbook(outfile)
  bold = workbook.add_format({'bold': 1})
  worksheet = workbook.add_worksheet()
  row = 1
  col = 0
  if compile_type and desc:
    worksheet.write('A1', 'IP Address', bold)
    worksheet.write('B1', 'Criticality', bold)
    worksheet.write('C1', 'Finding', bold)
    worksheet.write('D1', 'Description', bold)
    for ip, criticality, name, description in (findings):
      worksheet.write(row, col, ip)
      worksheet.write(row, col + 1, criticality)
      worksheet.write(row, col + 2, name)
      worksheet.write(row, col + 3, description)
      row += 1
  elif compile_type and not desc:
    worksheet.write('A1', 'IP Address', bold)
    worksheet.write('B1', 'Criticality', bold)
    worksheet.write('C1', 'Finding', bold)
    for ip, criticality, name in (findings):
      worksheet.write(row, col, ip)
      worksheet.write(row, col + 1, criticality)
      worksheet.write(row, col + 2, name)
      row += 1
  elif not compile_type and desc:
    worksheet.write('A1', 'Criticality', bold)
    worksheet.write('B1', 'IP Address', bold)
    worksheet.write('C1', 'Finding', bold)
    worksheet.write('D1', 'Description', bold)
    for criticality, ip, name, description in (findings):
      worksheet.write(row, col, criticality)
      worksheet.write(row, col + 1, ip)
      worksheet.write(row, col + 2, name)
      worksheet.write(row, col + 3, description)
      row += 1
  elif not compile_type and not desc:
    worksheet.write('A1', 'Criticality', bold)
    worksheet.write('B1', 'IP Address', bold)
    worksheet.write('C1', 'Finding', bold)
    for criticality, ip, name in (findings):
      worksheet.write(row, col, criticality)
      worksheet.write(row, col + 1, ip)
      worksheet.write(row, col + 2, name)
      row += 1
  workbook.close()

if __name__ == '__main__':
  banner()
  args = docopt(__doc__, version='NessuStrip version 1.0', options_first=True)
  soup = soup_nessus(args['INFILE'])
  findings = compile_findings(soup, args['host'], args['--desc'])
  if not args['OUTFILE']:
    outfile = os.path.splitext(args['INFILE'])[0] + ".xlsx"
    create_xlsx(findings, outfile, args['host'], args['--desc'])
  else:
    if not args['OUTFILE'].endswith('.xlsx'):
      print("%sError: The output file must end with .xlsx"% (R))
      pass
    else:
      create_xlsx(findings, args['OUTFILE'], args['host'], args['--desc'])