#!/usr/bin/python3

from io import StringIO
from http.client import InvalidURL
import os
from datetime import datetime
import pandas as pd
import numpy as np
import json
import traceback
import glob
import sys

PYTHON_MAJOR_VERSION = sys.version_info[0]

if PYTHON_MAJOR_VERSION == 3:
    import urllib.request as urlconnection
    from urllib.error import URLError, HTTPError
    from urllib.request import ProxyHandler
elif PYTHON_MAJOR_VERSION == 2:
    import urllib2 as urlconnection
    from urllib2 import HTTPError, URLError
    from httplib import InvalidURL

AGENT_HOME="/opt/site24x7/monagent"
LOG_FILE_DIR = os.path.join(AGENT_HOME, 'temp', 'scriptout')
LOG_ROTATION_INTERVAL='HOUR'




url="http://localhost:9000/haproxy_stats;csv"
username=None
password=None

#if any impacting changes to this plugin kindly increment the plugin version here.
PLUGIN_VERSION = "1"

#Setting this to true will alert you when there is a communication problem while posting plugin data to server
HEARTBEAT="true"

metrics      = { 'req_rate':'HTTP requests per second',
                 'rate':'Number of sessions created per second', # Existed
                 'ereq':'Number of request errors', # Existed
                 'dreq':'Requests denied due to security concerns',
                 'hrsp_4xx':'Number of HTTP client errors',
                 'hrsp_5xx':'Number of HTTP server errors',
                 'bin':'Number of bytes received', # Existed
                 'bout':'Number of bytes sent', # Existed
                 'qcur':'Current number of requests unassigned in queue', # Backend Existed,
                 'econ':'Number of requests that encountered an error attempting to connect server',
                 'dresp':'Responses denied due to security concerns',
                 'eresp':'Number of requests whose responses yielded an error',
                 'wredis':'Number of times a request was redispatched ',
                 'wretr' :'Number of times a connection was retried',
                 'qtime' :'The time in ms of the queue session',
                 'scur':'Current number of sessions',
                 'slim':'Session limit'
                 
                 }

applog_metrics= {'req_rate':'Request_Rate',
                 'rate':'Session_Rate', # Existed
                 'ereq':'Error_Requests', # Existed
                 'dreq':'Denied_Requests',
                 'hrsp_4xx':'Response_Code_4xx',
                 'hrsp_5xx':'Response_Code_5xx',
                 'bin':'Bytes_Received', # Existed
                 'bout':'Bytes_Sent', # Existed
                 'qcur':'Requests_in_Queue', # Backend Existed,
                 'econ':'Requests_Error_Attempting_to_Connect_Server',
                 'dresp':'Responses_Denied',
                 'eresp':'Responses_Yielded_an_Error',
                 'wredis':'Number_of_Redispatched_Requests',
                 'wretr' :'Number_of_Retried_Connections',
                 'qtime' :'Queue_Session_in_Millisecond',
                 'scur':'Current_Sessions',
                 'slim':'Session_Limit'
                 
                 }



class haproxy:

    def __init__(self,url,username,password,proxy,logs_enabled,log_type_name,log_file_path ):

        self.url=url
        self.username=username
        self.password=password
        self.proxy=proxy
        self.logsenabled=logs_enabled
        self.logtypename=log_type_name
        self.logfilepath=log_file_path        
        self.maindata={}
        self.maindata['plugin_version']=PLUGIN_VERSION
        self.maindata['heartbeat_required']=HEARTBEAT

    def openUrl(self):

        try:
            if (self.username and self.password):
                password_mgr = urlconnection.HTTPPasswordMgr()
                password_mgr.add_password(self.url, self.username, self.password)
                auth_handler = urlconnection.HTTPBasicAuthHandler(password_mgr)
                opener = urlconnection.build_opener(auth_handler)
                urlconnection.install_opener(opener)

            response = urlconnection.urlopen(self.url, timeout=10)

            if (response.status == 200):
                return response
            
            else:
                self.maindata['msg'] = 'Response status code from haproxy url is :'  + str(response.status)

        except HTTPError as e:
            self.maindata['msg'] ='Haproxy stats url has HTTP Error '+str(e.code)
        except URLError as e:
            #self.maindata['status'] = 0
            self.maindata['msg'] = 'Haproxy stats url has URL Error '+str(e.reason)
        except InvalidURL as e:
            #self.maindata['status'] = 0
            self.maindata['msg'] = 'Haproxy stats url is invalid URL'
        except Exception as e:
            #self.maindata['status'] = 0
            self.maindata['msg'] = 'Haproxy stats URL error : ' + str(e)  


    def gatherdata(self,csvdata):
        csvdata=csvdata.fillna(0)
        total=csvdata.shape[0]

        for i in range(total):
            for j in metrics:

                if csvdata.at[i,'svname']=="FRONTEND" and csvdata.at[i,'# pxname']=='stats':

                    val=csvdata.at[i,j]
                    if isinstance(val, np.integer):
                        val=int(val)
                    if isinstance(val, np.floating):
                        val=float(val)           
                    
                    self.maindata[csvdata.at[i,'# pxname']+'_'+csvdata.at[i,'svname']+'_'+metrics[j]]=val
                    
        for i in range(total):
            for j in metrics:

                if csvdata.at[i,'svname']=="BACKEND" and csvdata.at[i,'# pxname']=='stats':

                    val=csvdata.at[i,j]
                    if isinstance(val, np.integer):
                        val=int(val)
                    if isinstance(val, np.floating):
                        val=float(val)           
                    
                    self.maindata[csvdata.at[i,'# pxname']+'_'+csvdata.at[i,'svname']+'_'+metrics[j]]=val

        applog={}
        if(self.logsenabled in ['True', 'true', '1']):
                applog["logs_enabled"]=True
                applog["log_type_name"]=self.logtypename
                applog["log_file_path"]=self.logfilepath
        else:
                applog["logs_enabled"]=False
        self.maindata['applog'] = applog



    def metricCollector(self):
        try:
            response=self.openUrl()
            byte_response=response.read()
            str_response=byte_response.decode('utf-8')
            csvdata=pd.read_csv(StringIO(str_response))
            self.gatherdata(csvdata)
        except Exception as e:
            self.maindata['status']=0
            self.maindata['msg']=str(e)
    

    
    def getChildData(self):

        logdata=[]
        

        response=self.openUrl()
        byte_response=response.read()
        str_response=byte_response.decode('utf-8')
        csvdata=pd.read_csv(StringIO(str_response))
        csvdata=csvdata.fillna(0)
        total=csvdata.shape[0]
        

        for i in range(total):
            childdata={}

            if csvdata.at[i,'# pxname']==self.proxy:
                for j in metrics:

                    val=csvdata.at[i,j]
                    if isinstance(val, np.integer):
                        val=int(val)
                    if isinstance(val, np.floating):
                        val=float(val)           
                    
                    childdata[csvdata.at[i,'# pxname']+'_'+csvdata.at[i,'svname']+'_'+j]=val
            
            if childdata !={}:
                now = datetime.now()
                childdata["DateTime"]=str(now)
                logdata.append(childdata)
                
        return logdata



    def WriteAppLog(self):
        results=[]
        results=self.getChildData()
        

        file_suffix = datetime.now().strftime("%Y-%m-%d-%H" if LOG_ROTATION_INTERVAL == 'HOUR' else "%Y-%m-%d")
        #file_path = os.path.join(LOG_FILE_DIR, 'haproxy_webserver-'+file_suffix+'.log')
        file_path = os.path.join(LOG_FILE_DIR, 'haproxy_webserver'+'.log')

        with open(file_path, 'a') as _file:
            for child in results:
                _file.write(json.dumps(child))
                _file.write("\n")




    def CleanAppLog(self):
        try:
            inode_size_map = {}
            stat_file_name = os.path.join(AGENT_HOME, 'statefiles', 'local.properties')
            with open(stat_file_name) as _file:
                lines = _file.readlines()
                for line in lines:
                    if '=' in line:
                        line = line.strip()
                        inode_size_map[line.split('=')[0].strip()] = line.split('=')[1].strip() 
            
            log_files = glob.glob(os.path.join(LOG_FILE_DIR, 'childs-*.log'))
            sorted_files = sorted( log_files, key = lambda file: os.path.getmtime(file), reverse=True)
            for log_file in sorted_files[1:]:
                statusObj = os.stat(log_file)
                inode = str(statusObj.st_ino)
                lmtime = datetime.fromtimestamp(statusObj.st_mtime)
                time_delta = datetime.now() - lmtime 
                if (24 * time_delta.days + time_delta.seconds/3600) < 24:
                    file_size = statusObj.st_size
                    if inode in inode_size_map and file_size == int(inode_size_map[inode]):
                        os.remove(log_file)
                else:
                    os.remove(log_file)
        except Exception as e:
            traceback.print_exc(e)




    def ChildApplogManager(self):
        try:
            self.WriteAppLog()
            self.CleanAppLog()
        except:
            pass


if __name__=='__main__':

    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--url',help="URL Name",nargs='?', default= url)
    parser.add_argument('--username',help="Username" , default= username)
    parser.add_argument('--password',help="Password" , default= password)
    parser.add_argument('--proxy_name',help="Proxy Name" , default="allservers")
    parser.add_argument('--logs_enabled', help='enable log collection for this plugin application',default="False")
    parser.add_argument('--log_type_name', help='Display name of the log type', nargs='?', default=None)
    parser.add_argument('--log_file_path', help='list of comma separated log file paths', nargs='?', default=None)    

    args=parser.parse_args()

    url=args.url
    userame=args.username
    password=args.password
    proxy=args.proxy_name
    logsenabled=args.logs_enabled
    logtypename=args.log_type_name
    logfilepath=args.log_file_path

    hap=haproxy(url,username,password,proxy,logsenabled,logtypename,logfilepath)
    hap.metricCollector()
    print(json.dumps(hap.maindata,indent=True))
    hap.ChildApplogManager()
    