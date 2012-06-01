#!/usr/bin/python

import sys
import os, os.path
import urllib2
import datetime

import argparse
import gzip
import csv
                                                                                                                     
## Based on information at:                                                                                          
##  https://www.redhat.com/security/data/metrics/                                                                    
##  http://cve.mitre.org/                                                                                            
                                                                                                                     
CVE_ALLITEMS_GZ_URL='http://cve.mitre.org/data/downloads/allitems.csv.gz'
RHSA_MAP_CPE_TXT_URL='https://www.redhat.com/security/data/metrics/rhsamapcpe.txt'
CPE_DICT_URL='https://www.redhat.com/security/data/metrics/cpe-dictionary.xml'

def fetch(url,filename,force=False):
    if not os.path.exists(filename) or force:
        # fetch CVE stuff
        remote=urllib2.urlopen(CVE_ALLITEMS_GZ_URL)
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

class MissingArguments(object):
    def __init__(self,text):
        self.text=text
    def __str__(self):
        return self.text

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
                        metavar='<cve_list_file>')

    args = parser.parse_args()

    today=datetime.date.today()
    today_str=today.strftime('%Y-%m-%d')
    cve_csv_filename='cve-allitems-'+today_str+'.csv'
    cve_csv_gz_filename='cve-allitems-'+today_str+'.csv'
    rhsa2cve_filename='rhsamapcpe-'+today_str+'.txt'
    cpe_dict_filename='cpe-dictionary.xml'

    cve_candidates=args.cve_candidates

    failed_csv_filename='compiled/failed-'+today+'.csv'
    fixed_list_filename='compiled/fixed-'+today+'.txt'

    try:
        os.mkdir('compiled')
    except OSError:
        # directory exists, it's fine
        pass

    fetch(CVE_ALLITEMS_GZ_URL,cve_csv_gz_filename)
    fetch(RHSA_MAP_CPE_TXT_URL,rhsa2cve_filename)
    fetch(CPE_DICT_URL,cpe_dict_filename)

    cve_csv_gz=gzip.open(cve_csv_gz_filename,'r')
    rhsa2cve=open(rhsa2cve_filename,'r')
    # with cve_csv_gz, rhsa2cve:
    #      .....

    cve_reader=csv.reader(cve_csv_gz)
    for row in cve_reader:
        print(','.join(row))

    cve_csv_gz.close()
    rhsa2cve.close()



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
