from censys.ipv4 import *
from censys.base import *
from parser import process_parser

    
class censys_engine():
    def __init__(self,api_info):
        self.id = api_info['id']
        self.secret = api_info['secret']
        self.ip = api_info['ip']
        self.count = api_info['count']
        #fields:output
        self.fields = ["ip", "metadata.os", "protocols"]
    
    def start(self):
        print("-----------------------")
        print("Start Censys Process!!!")
        api = CensysIPv4(api_id=self.id,api_secret=self.secret)
        '''
        Step 1 : get port info & determine devicetypes
        '''    
        self.keywordMethod(api)
        #self.featureMethod(api)
        
        '''
        Step 2 : find Vulnerabilities
        '''

        '''
        Step 3 : offer solutions
        '''

        '''
        Step 4 : output
        '''

    def format(self,page):
        ip = page.get("ip","None")
        os = page.get("metadata.os","None")
        protocols = page.get("protocols","None")
        protocols = ", ".join([str(p.encode('UTF-8'), errors='ignore') for p in protocols])
        print("ip:" + ip, end = '\t')
        print("\n")

    def writeToFile(self,name,content):
        filename = "cens_log/" + name + ".log"
        f = open(filename,"a+")
        f.write(content)
        f.close()

    def keywordMethod(self,api):
        self.find_device(api,"printer")
        self.find_device(api,'router')
        self.find_device(api,'camera')

    def find_device(self,api,keyword):
        query = self.ip + ' and '+ keyword

        page_count = 0
        for page in api.search(query,self.fields):
            ip = page.get("ip","None")
            content = ip + ":" + keyword + "\n"
            self.writeToFile(keyword,content)
            print(ip+":"+keyword)
        
        if page_count == 0 :
            print(self.ip+":not "+keyword)
        
    def featureMethod(self,api):
        print(self.ip)
        info = api.view(self.ip)
        self.print_device_type(info)
    
    def print_device_type(self,info):
        if 'metadata' in info.keys():
            if 'device_type' in info['metadata'].keys():
                if info['metadata']['device_type'] == 'printer':
                    print('device type: printer\n')
                elif info['metadata']['device_type'] == 'camera':
                    print('device type: camera\n')
                elif info['metadata']['device_type'] == 'soho router':
                    print('device type: soho router\n')
        else: 
            print('device type: None\n')


if __name__ == "__main__":

    args = process_parser()

    api_info = dict()
    api_info['id'] = "440fac81-e807-4300-bcd7-92023c449af2"
    api_info['secret'] = "Dq84v4A9ryFmHqiIFJHMFN1MECcqV2fx"
    api_info['ip'] = args.ip
    api_info['count'] = args.count

    c = censys_engine(api_info)
    c.start()
