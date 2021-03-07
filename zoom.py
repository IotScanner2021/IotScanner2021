import sys
import re
import json
from zoomeye.sdk import ZoomEye
from parser import process_parser

class zoomeye_engine():
    
    def __init__(self,API_KEY,ip,count):
        self.api_key = API_KEY
        self.ip = ip
        self.count = count

    def start(self):
        print("-----------------------")
        print("Start Zoomeye Process!!!")    
        api = ZoomEye(api_key=self.api_key)

        '''
        Step 1 : get port info & determine devicetypes
        '''
        
        if self.count == 1:
            self.scan_port(api)
        else:
            self.scan_ports(api)
        
        '''
        Step 2 : find Vulnerabilities
        '''

        '''
        Step 3 : offer solutions
        '''

        '''
        Step 4 : output
        '''

    def json_output(self,data):
        j = json.dumps(data,indent=4)
        print(j)

    def writeToFile(self,name,content):
        filename = "zoom_log/" + name + ".log"
        f = open(filename,"a+")
        f.write(content)
        f.close()

    def scan_port(self,api):
        #pattern = "ip:\"" + self.ip + "\""
        pattern = self.ip
        #print(pattern)
        data = api.dork_search(pattern)
        #self.json_output(data)
        self.keywordMethod(data,self.ip)
        #self.featureMethod(data,self.ip)

    def scan_ports(self,api):
        pattern = "cidr:" + self.ip
        print(pattern)
        data = api.dork_search(pattern)

        num = 1
        for dataum in data:
            ip = dataum["ip"]
            self.json_output(dataum)
            self.keywordMethod(dataum,ip)
            #self.featureMethod(dataum,ip)
            num += 1

    def keywordMethod(self,data,ip):
        if self.category_rec(data,r"\brouter\b")==1:
            content = ip + ':router'
            self.writeToFile("router",content)
            print(ip+":router")
        elif self.category_rec(data,r"\bprinter\b")==1:
            content = ip + ':printer'
            self.writeToFile("printer",content)
            print(ip+":printer")
        elif self.category_rec(data,r"\bwap\b")==1:
            content = ip + ':camera'
            self.writeToFile("camera",content)
            print(ip+":camera")
        else:
            print(ip+":null")

    def category_rec(self,data, device):
        state = 0
        if isinstance(data,dict):
            for k,v in data.items():
                if type(v)==type(data):
                    state = self.category_rec(v, device)
                    if state == 1:
                        break
                else:
                    if re.search(device, str(v), re.I) != None:
                        state = 1
                        print(k,v)
                        break
        elif isinstance(data,list):
            for item in data:
                state = self.category_rec(item,device)
                if state == 1:
                    break
        return state

    def featureMethod(self,data,ip):
        
        if self.dev_product(data,"router") == 1:
            print(ip + ":router")
        elif self.dev_product(data,"printer") == 1:
            print(ip + ":printer")
        elif self.dev_product(data,"camera") == 1:
            print(ip + ":camera")


    def dev_product(self,data,product):
        state = 0
        if isinstance(data,dict):
            if re.search(product,data['portinfo']['device'],re.I) != None:
                return 1
            elif re.search(product,data['portinfo']['app'],re.I) != None:
                return 1
            else:
                return None
        elif isinstance(data,list):
            for item in data:
                state = self.dev_product(item,product)
                if state == 1:
                    return 1

if __name__ == "__main__":

    args = process_parser()
    ip = args.ip
    count = args.count

    if count == -1:
        count = 10000000000000000

    API_KEY = "7557767C-20cf-fd7d5-d848-d7a5904e8f1" 
    z = zoomeye_engine(API_KEY,ip,count)
    z.start()
