#!/usr/bin/env python3

# NessusParse v2.0
# By Ryan Roth

"""
Usage:  NessusParse INFILE [OUTFILE]
        NessusParse (-h | --help)
        NessusParse (-v | --version)

Options:
    -h, --help         Show this screen and exit
    -v, --version      Print the NessusParse version
"""

# Import requirements
import os, sys, time
import xlsxwriter
from docopt import docopt
from bs4 import BeautifulSoup

# Banner stuff
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

# A dictionary to map severity integers to textual rating
severity_dict = { 1: 'Low',
                  2: 'Moderate',
                  3: 'High',
                  4: 'Critical'}

# Make sure we're dealing with Nessus and then make soup
def soup_nessus(input):
  print("%s[-] Loading the Nessus file %s%s%s" % (Y, W, B, W))
  if not input.endswith('.nessus'):
    print("%sError: The input file must end with .nessus"% (R))
  else:
    try:
      with open(input,"r") as f:
        print("%s[-] Building XML objects %s%s%s" % (Y, W, B, W))
        soup = BeautifulSoup(f.read(),'xml')
        if not (soup.find().name) == "NessusClientData_v2":
          print("%sError: The input file is not a valid Nessus file"% (R))
          pass
        else:
          return soup
    except IOError as e:
      errno, strerror = e.args
      print("%sI/O error({0}): {1}".format(errno,strerror) % (R))
    except: #handle other exceptions such as attribute errors
      print("%sUnexpected error:", sys.exc_info()[0] % (R))
    pass

# Compile our findings
def compile_findings(soup):
  print("%s[-] Parsing the findings %s%s%s" % (Y, W, B, W))
  # empty holders to separate findings
  lows = []
  moderates = []
  highs = []
  criticals = []
  # iterate through the report hosts and items
  report_hosts = soup.find_all('ReportHost')
  for i in report_hosts:
    report_item = i.findChildren("ReportItem",recursive=True)
    for item in report_item:
      severity_int = int(item.get('severity'))
      if (severity_int == 1) or (severity_int == 2) or (severity_int == 3) or (severity_int == 4):
        # determine operating system
        if not i.find('tag', {'name': ['operating-system']}):
          os = "Unkown"
        else:
          os = i.find('tag', {'name': ['operating-system']}).getText()
        # gather the CVE details
        if not item.find('cve'):
          cve = "None"
        else:
          cve = item.cve.getText()
        # process the severity based on the dict assignments
        severity = severity_dict[int(item.get('severity'))]
        # build additional finding details
        summary = item.get('pluginName')
        port = item.get('port')
        ip = i.get('name')
        # assemble a finding
        finding = [severity, summary, ip, cve, port, os]
      # assign the finding to the appropriate list
      if severity_int == 1:
        lows.append(finding)
      if severity_int == 2:
        moderates.append(finding)
      if severity_int == 3:
        highs.append(finding)
      if severity_int == 4:
        criticals.append(finding)
    # concatenate all findings
    findings = [criticals,highs,moderates,lows]
  return findings

# Create the workbook
def create_xlsx(findings, outfile):
  # separate out the findings
  criticals = findings[0]
  highs = findings[1]
  moderates = findings[2]
  lows = findings[3]
  print("%s[-] Creating the Excel workbook: %s%s%s%s\n" % (Y, W, B, outfile, W))
  # instantiate a new workbook
  workbook = xlsxwriter.Workbook(outfile)
  # set header row format
  header_format = workbook.add_format({'bold': 1,
                                       'font_color': 'white',
                                       'font_size': '14',
                                       'bg_color': 'black',
                                       'font_name': 'Calibri',
                                       'valign': 'vcenter'
                                       })
  # set content cell format
  cell_format = workbook.add_format({'font_size': '12',
                                     'font_name': 'Calibri',
                                     })
  col = 0
  if criticals:
    row = 1
    worksheet_criticals = workbook.add_worksheet('Critical')
    worksheet_criticals.set_tab_color('#bf0000')
    worksheet_criticals.set_row(0, 25)
    worksheet_criticals.write('A1', 'Severity', header_format)
    worksheet_criticals.write('B1', 'Summary', header_format)
    worksheet_criticals.write('C1', 'IP/Hostname', header_format)
    worksheet_criticals.write('D1', 'CVE', header_format)
    worksheet_criticals.write('E1', 'Port', header_format)
    worksheet_criticals.write('F1', 'Operating System', header_format)
    for severity, summary, ip, cve, port, os in (criticals):
      worksheet_criticals.write(row, col, severity, cell_format)
      worksheet_criticals.write(row, col + 1, summary, cell_format)
      worksheet_criticals.write(row, col + 2, ip, cell_format)
      worksheet_criticals.write(row, col + 3, cve, cell_format)
      worksheet_criticals.write(row, col + 4, port, cell_format)
      worksheet_criticals.write(row, col + 5, os, cell_format)
      row += 1
  if highs:
    row = 1
    worksheet_highs = workbook.add_worksheet('High')
    worksheet_highs.set_tab_color('#bf0000')
    worksheet_highs.set_row(0, 25)
    worksheet_highs.write('A1', 'Severity', header_format)
    worksheet_highs.write('B1', 'Summary', header_format)
    worksheet_highs.write('C1', 'IP/Hostname', header_format)
    worksheet_highs.write('D1', 'CVE', header_format)
    worksheet_highs.write('E1', 'Port', header_format)
    worksheet_highs.write('F1', 'Operating System', header_format)
    for severity, summary, ip, cve, port, os in (highs):
      worksheet_highs.write(row, col, severity, cell_format)
      worksheet_highs.write(row, col + 1, summary, cell_format)
      worksheet_highs.write(row, col + 2, ip, cell_format)
      worksheet_highs.write(row, col + 3, cve, cell_format)
      worksheet_highs.write(row, col + 4, port, cell_format)
      worksheet_highs.write(row, col + 5, os, cell_format)
      row += 1
  if moderates:
    row = 1
    worksheet_moderates = workbook.add_worksheet('Moderate')
    worksheet_moderates.set_tab_color('#e89917')
    worksheet_moderates.set_row(0, 25)
    worksheet_moderates.write('A1', 'Severity', header_format)
    worksheet_moderates.write('B1', 'Summary', header_format)
    worksheet_moderates.write('C1', 'IP/Hostname', header_format)
    worksheet_moderates.write('D1', 'CVE', header_format)
    worksheet_moderates.write('E1', 'Port', header_format)
    worksheet_moderates.write('F1', 'Operating System', header_format)
    for severity, summary, ip, cve, port, os in (moderates):
      worksheet_moderates.write(row, col, severity, cell_format)
      worksheet_moderates.write(row, col + 1, summary, cell_format)
      worksheet_moderates.write(row, col + 2, ip, cell_format)
      worksheet_moderates.write(row, col + 3, cve, cell_format)
      worksheet_moderates.write(row, col + 4, port, cell_format)
      worksheet_moderates.write(row, col + 5, os, cell_format)
      row += 1
  if lows:
    row = 1
    worksheet_lows = workbook.add_worksheet('Low')
    worksheet_lows.set_tab_color('#ffff00')
    worksheet_lows.set_row(0, 25)
    worksheet_lows.write('A1', 'Severity', header_format)
    worksheet_lows.write('B1', 'Summary', header_format)
    worksheet_lows.write('C1', 'IP/Hostname', header_format)
    worksheet_lows.write('D1', 'CVE', header_format)
    worksheet_lows.write('E1', 'Port', header_format)
    worksheet_lows.write('F1', 'Operating System', header_format)
    for severity, summary, ip, cve, port, os in (lows):
      worksheet_lows.write(row, col, severity, cell_format)
      worksheet_lows.write(row, col + 1, summary, cell_format)
      worksheet_lows.write(row, col + 2, ip, cell_format)
      worksheet_lows.write(row, col + 3, cve, cell_format)
      worksheet_lows.write(row, col + 4, port, cell_format)
      worksheet_lows.write(row, col + 5, os, cell_format)
      row += 1
  workbook.close()

if __name__ == '__main__':
  banner()
  args = docopt(__doc__, version='NessusParse version 2.0', options_first=True)
  soup = soup_nessus(args['INFILE'])
  findings = compile_findings(soup)
  if not args['OUTFILE']:
      outfile = os.path.splitext(args['INFILE'])[0] + ".xlsx"
      create_xlsx(findings, outfile)
  else:
    if not args['OUTFILE'].endswith('.xlsx'):
      print("%sError: The output file must end with .xlsx"% (R))
      pass
    else:
      create_xlsx(findings, args['OUTFILE'])
  print("%s[*] Process completed successfully %s%s%s" % (G, W, B, W))