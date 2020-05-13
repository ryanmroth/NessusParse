# NessusParse
Parses Nessus XML files and outputs Excel workbooks.
The Excel sheets in the workbook are organized by criticality.
NessusParse ignores items with an 'Informational' or 'None' criticality rating.

### Installation

NessusParse requires:
  [Docopt](http://docopt.org/)
  [Lxml](https://lxml.de/)
  [BeautifulSoup](https://pypi.org/project/beautifulsoup4/)
  [XlsxWriter](https://xlsxwriter.readthedocs.io/)

#### Install the dependencies

```sh
$ cd NessusParse
$ pip install -r requirements.txt
```

### Usage

```sh
$ Usage:  NessusParse INFILE [OUTFILE]
          NessusParse (-h | --help)
          NessusParse (-v | --version)

$ Options:
    -h, --help         Show this screen and exit
    -v, --version      Print the NessusParse version
```
* Note: Output file is optional. Defaults to 'INFILE.xlsx' in CWD

### License

MIT License

**Free Software, Hell Yeah!**
