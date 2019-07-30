# NessusParse
Parses Nessus XML files and outputs simple Excel files.
The Excel files can be sorted by criticality or by host.
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
$ pip install requirements.txt
```

### Usage

```sh
$ Usage:  NessusParse [options] (host | criticality) INFILE [OUTFILE]
          NessusParse (-h | --help)
          NessusParse (-v | --version)

$ Required Options:
    host               Output file sorted by host
    criticality        Output file sorted by criticality

$ Options:
    -d, --desc         Include description of the finding
    -h, --help         Show this screen and exit
    -v, --version      Print the NessusParse version
```
* Note: Output file is optional. Defaults to 'INFILE.xlsx' in CWD

### License

MIT License

**Free Software, Hell Yeah!**
