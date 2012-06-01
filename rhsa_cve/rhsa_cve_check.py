#!/usr/bin/python

from __future__ import print_function

import sys
import os, os.path
import urllib2
import datetime

import argparse
import gzip
import csv
import re

from UserDict import UserDict

from xml.dom.minidom import parse as minidom_parse
# from xml.etree.ElementTree import ElementTree

                                                                                                                     
## Based on information at:                                                                                          
##  https://www.redhat.com/security/data/metrics/                                                                    
##  http://cve.mitre.org/                                                                                            
                                                                                                                     
CVE_ALLITEMS_GZ_URL='http://cve.mitre.org/data/downloads/allitems.csv.gz'
RHSA_MAP_CPE_TXT_URL='https://www.redhat.com/security/data/metrics/rhsamapcpe.txt'
CPE_DICT_URL='https://www.redhat.com/security/data/metrics/cpe-dictionary.xml'

def fetch(url,filename,force=False):
    if not os.path.exists(filename) or force:
        # fetch CVE stuff
        print("Fetching {0} from {1}".format(filename,url))
        remote=urllib2.urlopen(url)
        local=open(filename,'w')
        can=True
        while can:
            buf=remote.read(1024)
            if buf:
                local.write(buf)
            else:
                can=False
        remote.close()
        local.close()

def isEmpty(my_list):
    for i in my_list:
        if i:
            return False
    return True

class MissingArguments(object):
    def __init__(self,text):
        self.text=text
    def __str__(self):
        return self.text

class CVEList(UserDict):
    _filter=None
    def __init__(self,filename=None):
        UserDict.__init__(self)
        if filename:
            self.load(filename)
            
        self._filter=None
        self._ref_re=re.compile(r' +\| +')

    def setFilter(self,filter):
        """List only items that match filter"""
        self._filter=filter

    def load(self,filename):
        with open(filename,'r') as f:
            self._load(f)
    
    def load_gz(self,filename):
        with gzip.open(filename,'r') as f:
            self._load(f)
        

    def _load(self,file):
        # with cve_csv_gz, rhsa2cve:
        #      .....
        reader=csv.reader(file)
        ## 1. read line #3  for field names
        ## 2. read the rest of the file after empty line
        
        while reader.line_num<3:
            row=reader.next()

        base_dict=row
        # print( base_dict)
        
        while not isEmpty(row):
            row=reader.next()
            
        # now we're at empty row
        
        for row in reader:
            # print(row[0])
            cve_id=row[0]
            if self._filter:
                # print("filter...")
                if not (cve_id in self._filter):
                    continue
            raw_dict=dict(zip(base_dict,row))
            ref_list=self._ref_re.split(raw_dict['References'])
            raw_dict['References']=ref_list
            self.data[cve_id]=dict(zip(base_dict,row))

class CPEDict(UserDict):
    """CPE dictionary object"""
    
    def __init__(self,filename=None):
        UserDict.__init__(self)
        if filename:
            self.load(filename)
        
    def load(self,filename):
        # cpe_tree=ElementTree()
        # cpe_list=cpe_tree.parse(filename)
        cpe_list=minidom_parse(filename)

        # print(cpe_list)
        for ci in cpe_list.getElementsByTagName('cpe-item'):
            # print('found item')
            ci_title_elem=ci.getElementsByTagName('title')[0]
            self.data[ci.getAttribute("name")]=ci_title_elem.firstChild.nodeValue
            
class Analizer(object):
    cve_csv_filename=None
    cve_csv_file=None

    cve_csv_gz_filename=None
    cve_csv_gz_file=None

    cve_csv_reader=None

    rhsa2cve_filename=None
    rhsa2cve_file=None

    cpe_dict_filename=None
    cpe_dict_file=None

    def __init__(self,cve_csv=None,cve_csv_gz=None,rhsa2cve=None,cpe_dict=None):
        if not cve_csv_gz is None:
            self.set_cve_csv_gz(cve_csv_gz)
        elif not cve_csv is None:
            self.set_cve_csv(cve_csv)
        if None in (rhsa2cve,cpe_dict):
            raise MissingArguments('not enough arguments passed to __init__')

    def set_cve_csv(self,cve_csv):
        cve_csv_file=open(cve_csv,'r')
        self.cve_csv_reader=csv.reader(cve_csv_file)
        self.cve_csv_file=cve_csv_file
        self.cve_csv_filename=cve_csv
            
    def set_cve_csv_gz(self,cve_csv_gz):
        cve_csv_gz_file=gzip.open(cve_csv_gz,'r')
        # with cve_csv_gz, rhsa2cve:
        #      .....
        self.cve_csv_reader=csv.reader(cve_csv_gz_file)
        self.cve_csv_gz_file=cve_csv_gz_file
        self.cve_csv_gz_filename=cve_csv_gz

    def set_rhsa2cve(self,rhsa2cve):
        self.rhsa2cve_filename=rhsa2cve
        self.rhsa2cve_file=open(rhsa2cve,'r')

    def set_cpe_dict(self,cpe_dict):
        self.cpe_dict_filename=cpe_dict
        ##XXX now we need to open this XML and extract dictionary of 
        ##XXX CPE descriptors

def main(argv):
    parser = argparse.ArgumentParser(description='RHSA & CVE cross-reference tool')
    parser.add_argument('cve_candidates',type=str,help="name of the file listing CVE's",
                         metavar='<cve_list_file>', default=None)
     
    args = parser.parse_args(argv[1:])

    today=datetime.date.today()
    today_str=today.strftime('%Y-%m-%d')
    cve_csv_filename='cve-allitems-'+today_str+'.csv'
    cve_csv_gz_filename='cve-allitems-'+today_str+'.csv.gz'
    rhsa2cve_filename='rhsamapcpe-'+today_str+'.txt'
    cpe_dict_filename='cpe-dictionary.xml'

    if args.cve_candidates:
        cve_candidates=args.cve_candidates
    else:
        cve_candidates='need_to_fix'

    f=open(cve_candidates,'r')
    a=f.read()
    f.close()
        
    cve_filter=a.split()
    # print(a)
    # print(cve_filter)

    failed_csv_filename='compiled/failed-'+today_str+'.csv'
    fixed_list_filename='compiled/fixed-'+today_str+'.txt'

    try:
        os.mkdir('compiled')
    except OSError:
        # directory exists, it's fine
        pass

    fetch(CVE_ALLITEMS_GZ_URL,cve_csv_gz_filename)
    fetch(RHSA_MAP_CPE_TXT_URL,rhsa2cve_filename)
    fetch(CPE_DICT_URL,cpe_dict_filename)
    
    cpe=CPEDict(cpe_dict_filename)
    cve=CVEList()
    cve.setFilter(cve_filter)
    cve.load_gz(cve_csv_gz_filename)
    print(cve)
    return

    rhsa2cve=open(rhsa2cve_filename,'r')
    # with cve_csv_gz, rhsa2cve:
    #      .....


    rhsa2cve.close()


if __name__ == '__main__':
    main(sys.argv)


##### SHELL ######
#===============================================================================
# 
# echo ""> $fixed_list
# # we need line #3 with header...
# sed -n '3p' ${cve_csv} > $failed_csv
# 
# for cve in $(cat ${cve_candidates}) 
#  do 
#   if grep $cve ${rhsa2cve_file} >> $fixed_list 
#      then
#        echo "===> $cve OK"
#      else
#        echo "===> $cve FAILED"
#        grep $cve ${cve_csv} >> $failed_csv
#   fi
#  done 
#===============================================================================
