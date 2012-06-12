#!/usr/bin/python

from __future__ import print_function

import sys
import os.path
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

class NoFlagDefined(object):
    def __init__(self,text):
        self.text=text
    def __str__(self):
        return self.text

class Flags(object):
    _flags=None
    def __init__(self):
        self._flags={}
    
    def __getattr__(self,name):
        if self._flags.has_key(name):
            return self._flags[name]
        else:
            raise NoFlagDefined(name)
        
    def __setattr__(self,name,value):
        if name=='_flags':
            object.__setattr__(self, name, value)
        self._flags[name]=value

class Rhsa2CveMap(UserDict):

    _filter=None
    _cpe_filter=None
    
    def __init__(self,filename=None):
        UserDict.__init__(self)
        if filename:
            self.load(filename)
        self._filter=None

    def setLoadFilter(self,lfilter):
        """List only items that match filter"""
        self._filter=lfilter

    def setLoadCPEFilter(self,lfilter):
        """List only items that fuzzy-match filter:
        start with the same string"""
        self._cpe_filter=lfilter



    def load(self,filename):
        if self._filter:
            # set is going to be better in managing tasks we have at hand
            filter_set=set(self._filter)
        else:
            filter_set=False
        
        with open(filename,'r') as f:
            for line in f:
                (rhsa,cve_list,cpe_list)=line.split()
                rhsa_dict={}
                cve=cve_list.split(',')
                if self._filter:
                    cve_set=set(cve)
                    if filter_set.isdisjoint(cve_set):
                        continue
                    else:
                        cve=list(cve_set.intersection(filter_set))
                    
                cpe=[]
                cpe_raw=cpe_list.split(',')
                for c in cpe_raw:
                    # print(c)
                    filterOut=True
                    if self._cpe_filter:
                        for cf in self._cpe_filter:
                            if c[:len(cf)] == cf:
                                filterOut=False
                                ##DEBUG print('Found {0} matching {1}'.format(c,cf))
                                break
                    else:
                        filterOut=False
                    if filterOut:
                        continue
                    elements=c.split(':')
                    try:
                        ed,package=elements[-1].split('/')
                    except ValueError:
                        ed=elements[-1]
                        package=None
                        print("WARNING: can't parse: ",c)
                        continue
                    t=elements[:-1]+[ed]
                    cpe_lookup=":".join(t)
                    cpe_dict={'base':cpe_lookup,'uri':c,'package':package}
                    cpe.append(cpe_dict)
                    
                rhsa_dict['CPE']=cpe
                rhsa_dict['CVE']=cve
                self.data[rhsa]=rhsa_dict

class CVEList(UserDict):
    _filter=None
    def __init__(self,filename=None):
        UserDict.__init__(self)
        if filename:
            self.load(filename)
            
        self._filter=None
        self._ref_re=re.compile(r' +\| +')

    def setLoadFilter(self,lfilter):
        """List only items that match filter"""
        self._filter=lfilter

    def load(self,filename):
        with open(filename,'r') as f:
            self._load(f)
    
    def load_gz(self,filename):
        with gzip.open(filename,'r') as f:
            self._load(f)
        

    def _load(self,file_handle):
        reader=csv.reader(file_handle)
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
    _filter=None
    def __init__(self,filename=None):
        UserDict.__init__(self)
        if filename:
            self.load(filename)
            
        self._filter=None

    def setLoadFilter(self,lfilter):
        self._filter=lfilter
        
    def load(self,filename):
        # cpe_tree=ElementTree()
        # cpe_list=cpe_tree.parse(filename)
        cpe_list=minidom_parse(filename)

        # print(cpe_list)
        for ci in cpe_list.getElementsByTagName('cpe-item'):
            # print('found item')
            ci_title_elem=ci.getElementsByTagName('title')[0]
            self.data[ci.getAttribute("name")]=ci_title_elem.firstChild.nodeValue
            
class CveRhsaAnalyzer(object):

    _cve_dict=None
    _cpe_dict=None
    _rhsa2cve_dict=None
    
    def __init__(self,cve,rhsa2cve,cpe):
        self.setCpeDict(cpe)
        self.setCveDict(cve)
        self.setRhsa2CveDict(rhsa2cve)

    def setCveDict(self,cve):
        self._cve_dict=cve
        
    def setCpeDict(self,cpe):
        self._cpe_dict=cpe
        
    def setRhsa2CveDict(self,rhsa2cve):
        self._rhsa2cve_dict=rhsa2cve
    
    def get_cve_compliance_report(self):
        """Map out CVE->RHSA with attached package names affected
        Returns tuple: (CVE-ID:str,Fixed:bool,RHSA:list,pkgs:set)"""
        #TODO add ability to generate package->CVE list for automated checking  
        cve=self._cve_dict
        # cpe=self._cpe_dict
        rhsa2cve=self._rhsa2cve_dict
        
        rev_map={}
        for rhsa in rhsa2cve.keys():
            cve_list=rhsa2cve[rhsa]['CVE']
            for c in cve_list:
                if rev_map.has_key(c):
                    rev_map[c].append(rhsa)
                else:
                    rev_map[c]=[rhsa]
            # print(rhsa, ",".join(cve_list))
        report=[]
        for cve_name in cve.keys():
            if rev_map.has_key(cve_name):
                rev_lookup=rev_map[cve_name]
                # print(rev_lookup)
                pkg_set=set()
                for r in rev_lookup:
                    cpe_list=rhsa2cve[r]['CPE']
                    for cpe_item in cpe_list:
                        pkg_set.add(cpe_item['package'])
                # print(cve_name,",".join(rev_lookup),",".join(pkg_list))
                report.append((cve_name,True,rev_lookup,pkg_set))
            else:
                # print(cve_name,"NOT FIXED")
                report.append((cve_name,False,(),()))
        return report
        
    def get_package_cve_map(self,cve_report=None):
        """create a list of packages with CVE items to check"""
        # we need something we can use for meta-loop:
        # for p in packages:
        #   login to server
        #   rpm --changelog -q $p | grep $cve 
        # cve=self._cve_dict
        # cpe=self._cpe_dict
        # rhsa2cve=self._rhsa2cve_dict
        pkg_dict={}
        if not cve_report:
            cve_report=self.get_cve_compliance_report()
        for (cve_id,status,rhsa,pkg_set) in cve_report:
            if status:
                for p in pkg_set:
                    if not pkg_dict.has_key(p):
                        pkg_dict[p]=[]
                    pkg_dict[p].append(cve_id)
        return pkg_dict

class CheckApplication(object):

    ############# Private properties ##########
    
    _cve_candidates_filename=None
    _cve_dict=None
    _cve_dict_filename=None
    _cpe_dict=None
    _cpe_dict_filename=None
    _rhsa2cve_dict=None
    _rhsa2cve_dict_filename=None

    _failed_csv_filename=None
    _fixed_list_filename=None
    _check_cve_script_filename=None
    _check_pkg_script_filename=None
    
    
    _cpe_filter=None
    _cve_filter=None
    
    _app_flags=None
    _app_args=None
    _app_parser=None


    ############# Public Properties ###########
    
    @property
    def cve(self):
        return self._cve_dict
    
    @property
    def cpe(self):
        return self._cpe_dict
    
    @property
    def rhsa2cve(self):
        return self._rhsa2cve_dict

    @property
    def flags(self):
        return self._app_flags
    
    ############# Methods ############### 

    def setDefaults(self):
        today=datetime.date.today()
        today_str=today.strftime('%Y-%m-%d')

        self._cve_dict_filename='cve-allitems-'+today_str+'.csv.gz'
        # cve_csv_gz_filename='cve-allitems-'+today_str+'.csv.gz'
        self._rhsa2cve_dict_filename='rhsamapcpe-'+today_str+'.txt'
        self._cpe_dict_filename='cpe-dictionary.xml'
        
        # print(a)
        # print(cve_filter)
    
        self._failed_csv_filename='compiled/failed-'+today_str+'.csv'
        self._fixed_list_filename='compiled/fixed-'+today_str+'.txt'
        self._check_cve_script_filename='compiled/check-cve-'+today_str+'.sh'
        self._check_pkg_script_filename='compiled/check-pkg'+today_str+'.sh'
        self.flags.default_compiled_filenames=True
    
    
        # return (cve_csv_gz_filename,rhsa2cve_filename,cpe_dict_filename)

    def setupFiles(self):
        ## should be called after everything else is parsed and settled
        try:
            if self.flags.default_compiled_filenames:
                os.mkdir('compiled')
        except OSError:
            # directory exists, it's fine
            pass
        fetch(CVE_ALLITEMS_GZ_URL,self._cve_dict_filename)
        fetch(RHSA_MAP_CPE_TXT_URL,self._rhsa2cve_dict_filename)
        fetch(CPE_DICT_URL,self._cpe_dict_filename)


    def createParser(self):
        parser = argparse.ArgumentParser(description='RHSA & CVE cross-reference tool')
        parser.add_argument('cve_candidates',type=str,help="name of the file listing CVE's",
                             metavar='<cve_list_file>', default=None)
        parser.add_argument('--cpe-filter',type=str,help="comma-delimited CPE URI filters",
                            required=False,default=None)
        parser.add_argument('--print-packages','-p',help="Print list of packages involved",action='store_const',
                            const=True,default=False,required=False)
        parser.add_argument('--print-brief','-b',help="Print brief general report",action='store_const',
                            const=True,default=False,required=False)

        parser.add_argument('--compile-failed','-F',type=str, nargs='?',help="Compile list of failed entries",
                            const=self._failed_csv_filename,default=None,required=False)
        parser.add_argument('--compile-fixed','-f',type=str, nargs='?', help="Compile list of addressed entries",
                            const=self._fixed_list_filename,default=None,required=False)

        parser.add_argument('--compile-cve-check-script','-s',type=str, nargs='?',help="Compile script to run on checked host",
                            metavar='CVE_SCRIPT_NAME',const=self._check_cve_script_filename,default=None,required=False)

        parser.add_argument('--compile-pkg-check-script','-S',type=str, nargs='?',help="Compile script to run on checked host",
                            metavar='PKG_SCRIPT_NAME',const=self._check_pkg_script_filename,default=None,required=False)

        self._app_parser=parser
        return self._app_parser
        
    def _parseArgs(self,argv):
        ## defaults must be set before calling this method
        args = self._app_parser.parse_args(argv)
        self._app_args=args

        if args.cve_candidates:
            self._cve_candidates_filename=args.cve_candidates
        else:
            self._cve_candidates_filename='need_to_fix'
            
        if args.cpe_filter:
            self._cpe_filter=args.cpe_filter.split(',')
            self.flags.cpe_filtered=True
        else:
            self._cpe_filter=()
            self.flags.cpe_filtered=False
            
        self.flags.print_package_report=args.print_packages
        self.flags.print_brief_report=args.print_brief
        
        self.flags.default_compiled_filenames=False
        if args.compile_failed:
            self.flags.compile_failed=True
            if self._failed_csv_filename == args.compile_failed:
                self.flags.default_compiled_filenames=True
            self._failed_csv_filename=args.compile_failed
        else:
            self.flags.compile_failed=False
            
        if args.compile_fixed:
            self.flags.compile_fixed=True
            if self._fixed_list_filename == args.compile_fixed:
                self.flags.default_compiled_filenames=True
            self._fixed_list_filename=args.compile_fixed
        else:
            self.flags.compile_fixed=False
            
        if args.compile_cve_check_script:
            self.flags.compile_cve_check_script=True
            if self._check_cve_script_filename == args.compile_cve_check_script:
                self.flags.default_compiled_filenames=True
            self._check_cve_script_filename=args.compile_cve_check_script
        else:
            self.flags.compile_cve_check_script=False
        
        if args.compile_pkg_check_script:
            self.flags.compile_pkg_check_script=True
            if self._check_pkg_script_filename == args.compile_pkg_check_script:
                self.flags.default_compiled_filenames=True
            self._check_pkg_script_filename=args.compile_pkg_check_script
        else:
            self.flags.compile_pkg_check_script=False

    def __init__(self,argv):
         
        self._app_flags=Flags()
        
        self.setDefaults()

        self.createParser()
       
        self._parseArgs(argv[1:])

        self.setupFiles()
        

        with open(self._cve_candidates_filename,'r') as f:
            cve_list_str=f.read()
        
        # all we have to do is split giant string
        # into CVE items:
        self._cve_filter=cve_list_str.split()

        cpe=CPEDict(self._cpe_dict_filename)
        cve=CVEList()
        cve.setLoadFilter(self._cve_filter)
        cve.load_gz(self._cve_dict_filename)
        rhsa=Rhsa2CveMap()
        rhsa.setLoadFilter(self._cve_filter)
        if self.flags.cpe_filtered:
            # rhsa.setLoadCPEFilter(['cpe:/o:redhat:enterprise_linux'])
            rhsa.setLoadCPEFilter(self._cpe_filter)
        rhsa.load(self._rhsa2cve_dict_filename)
        
        self._cpe_dict=cpe
        self._cve_dict=cve
        self._rhsa2cve_dict=rhsa

    def execApp(self):
        # (cve,rhsa,cpe)=(self._cve_dict,self._rhsa2cve_dict,self._cpe_dict)

        cr=CveRhsaAnalyzer(self.cve,self.rhsa2cve,self.cpe)
        report=cr.get_cve_compliance_report()

        self.printReports(cr,report)
        self.createCveReportFiles(cr, report)

    def printBriefReport(self, report):
        for cve_id, status, rhsa_list, pkg_list in report:
            if status:
                print( cve_id, ",".join(rhsa_list), ",".join(pkg_list))
            else:
                print( cve_id, 'NOT FIXED')

    def printPackageReport(self, cr, report):
        pkg_cve = cr.get_package_cve_map(report)
        for pkg in pkg_cve.keys():
            print( pkg, ",".join(pkg_cve[pkg]))

    def _processDefaults(self, cra, cve_report):
        """Helper method to set up CveRhsaAnalyzer and produce
        cve_compliance_report for further processing as needed"""
        if cra:
            cr = cra
        else:
            cr = CveRhsaAnalyzer(self.cve, self.rhsa2cve, self.cpe)
        if cve_report:
            report = cve_report
        else:
            report = cr.get_cve_compliance_report()
        return report, cr

    def printReports(self,cra=None,cve_report=None):
        report, cr = self._processDefaults(cra, cve_report)

        if self.flags.print_brief_report:
            self.printBriefReport(report)
        if self.flags.print_package_report:
            self.printPackageReport(cr, report)

    def createFailedFile(self, report):
        writer = csv.writer(open(self._failed_csv_filename, 'wb'), quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow(["Name", "Status", "Description", "Phase", "Comments"])
        for cve_id, status, rhsa_list, pkg_list in report:
            if not status:
                cve_item = self.cve[cve_id]
                writer.writerow((cve_id, cve_item["Status"], cve_item["Description"], cve_item["Phase"], cve_item["Comments"]))
        
    def createFixedFile(self,report):
        with open(self._fixed_list_filename,'w') as f:
            for (cve_id,status,rhsa_list,pkg_list) in report:
                if status:
                    print(cve_id,",".join(rhsa_list),",".join(pkg_list),file=f)

    def createPackageCheckScript(self, cr, report):
        ##TODO
        # we need to implement real method here...
        #
        with open(self._check_pkg_script_filename,'w') as check_scr:
            pkg_cve = cr.get_package_cve_map(report)
            for pkg in pkg_cve.keys():
                cond_str="if rpm -q --quiet {0} ; then {{".format(pkg)
                print(cond_str,file=check_scr)
                for cve in pkg_cve[pkg]:
                    check_str="if rpm --changelog -q {0} | grep -qF '{1}' ; then echo '{0}: {1} FIXED'; else echo '{0}: {1} FAILED'; fi".format(pkg,cve)
                    print(check_str,file=check_scr)
                    
                print("} else echo '"+pkg+": not installed'; fi",file=check_scr)
        
    def createCveCheckScript(self, cr, report):
        # for c in cve
        #   print $c
        #   for p in pkg_cve.keys()
        #       if package_installed:
        #          if grep $c rpm-changelog $p
        #             print FIXED
        #          else
        #             print NOT FIXED
        #       else
        #          print as per RHSA $X $p is not installed to satisfy $c
        with open(self._check_cve_script_filename,'w') as check_scr:
            for (cve_id,status,rhsa_list,pkg_list) in report:
                if not status:
                    ## CVE doesn't map to RHSA
                    print("echo '{0}: is not covered by RHSA'".format(cve_id),file=check_scr)
                else:
                    ## CVE mapped to RHSA-list
                    if not pkg_list:
                        print('echo "{0}: can\'t find associated packages via RHSA"'.format(cve_id),file=check_scr)
                    for pkg in pkg_list:
                        ## walk the pkg_list now
                        cond_str="if rpm -q --quiet {0} ; then {{".format(pkg)
                        print(cond_str,file=check_scr)
                        # check_str="if rpm --changelog -q {0} | grep -qF '{1}' ; then echo '{1}: {0} {2} FIXED'; else for r in {3} ; do if rpm --changelog -q {0}  | grep -qF $r ; then  echo '{1}: {0} {2} FIXED; else '{1}: {0} {2} FAILED'; fi; done; fi".format(pkg,cve_id,",".join(rhsa_list)," ".join(rhsa_list))
                        check_str="if rpm --changelog -q {0} | grep -qF '{1}' ; then echo '{1}: {0} {2} FIXED'; else echo '{1}: {0} {2} FAILED'; fi".format(pkg,cve_id,",".join(rhsa_list))
                        print(check_str,file=check_scr)
                        print("} else echo '"+pkg+": not installed'; fi",file=check_scr)
        
    def createCveReportFiles(self,cra=None,cve_report=None):
        report, cr = self._processDefaults(cra, cve_report)
            
        if self.flags.compile_failed:
            self.createFailedFile(report)
        if self.flags.compile_fixed:
            self.createFixedFile(report)
        if self.flags.compile_cve_check_script:
            self.createCveCheckScript(cr,report)
        

if __name__ == '__main__':
    ca=CheckApplication(sys.argv)
    ca.execApp()

