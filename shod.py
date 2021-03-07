import shodan
import json
import sys
from time import sleep
from parser import process_parser

class shodan_engine():
    def __init__(self,API_KEY,ip,count):
        self.api_key = API_KEY
        self.ip = ip
        self.count = count
    
    def  start(self):
        print("----------------------")
        print("Start Shodan Process!!!")
        api = shodan.Shodan(self.api_key)
        
        '''
        Step 1: get port info & determine devicetypes
        '''
        if self.count == 1:
            self.scan_port(api)
        else:
            mask = self.ip.split('/')[1]
            if mask == "16":
                self.scan_ports_mask16(api)
            elif mask == "24":
                self.scan_ports_mask24(api)
        '''
        Step 2: find Vulnerabilities
        '''
        
        '''
        Step 2 : find Vulnerabilities
        '''

        '''
        Step 3 : offer solutions
        '''

        '''
        Step 4 : output
        '''


    #scan 1 port
    def scan_port(self,api):
        print("Scan 1 port")
        info = api.host(self.ip)
        #self.json_output(info)
        #self.featureMethod(info)
        self.keywordMethod(info,self.ip)

    #scan mask 16
    def scan_ports_mask16(self,api):
        print("Scan ports(mask 16)")
        ip = self.ip
        ip_str = "".join([ip.split('.')[0],".",ip.split('.')[1]])
        for i in range(0,256,1):
            for j in range(0,256,1):
                if j==self.count:
                    return
                ip = ip_str + "." + str(i) + '.' + str(j)
                try:
                    info = api.host(ip)
                    self.keywordMethod(info,ip)
                    #self.featureMethod(info)
                    sleep(1.5)
                except shodan.APIError as e:
                    print(e)
    
    #scan mask 24
    def scan_ports_mask24(self,api):
        print("Scan ports(mask 8)")
        ip = self.ip
        ip_str = "".join([ip.split('.')[0],".",ip.split('.')[1],".",ip.split('.')[2]])
        for i in range(0,256,1):
                if i==self.count:
                    return
                ip = ip_str + "." + str(i)
                try:
                    info = api.host(ip)
                    #self.featureMethod(info)
                    self.keywordMethod(info,ip)
                    sleep(1.5)
                except shodan.APIError as e:
                    print(e)

    def json_output(self,info):
        j = json.dumps(info,indent=4)
        print(j)
    
    def writeToFile(self,name,content):
        filename = "shod_log/" + name + ".log"
        f = open(filename,"a+")
        f.write(content)
        f.close()

    ## use keyword to determine devie
    def keywordMethod(self,info,ip):
        printer = self.json_extract(info, 'printer')
        camera = self.json_extract(info, 'camera')
        router = self.json_extract(info, 'router')
        
        if len(printer) > 0:
            content = ip + ":printer" + "\n"
            self.writeToFile("printer",content)
            print(ip + ":printer")
        elif len(router) > 0:
            content = ip + "router" + "\n"
            self.writeToFile("router",content)
            print(ip + ":router")
        elif len(camera) > 0:
            content = ip + ":camera" + "\n"
            self.writeToFile("camera",content)
            print(ip + ":camera")

    ## if dict else list -> dict
    def json_extract(self,info,keyword):
        elements = []
        self.extract(info, elements, keyword)
        return elements

    def extract(self,info,elements,keyword):
        ## tell whether have keryword and where to find keyword 
        if isinstance(info, dict):
            for key, value in info.items():
                if isinstance(value,(dict,list)):
                    self.extract(value, elements, keyword)
                elif keyword in str(key).lower():
                    elements.append(str(key))
                    elements.append(str(value))
                    break
                elif keyword in str(value).lower():
                    elements.append(str(key))
                    elements.append(str(value))
                    break
        elif isinstance(info,list):
            for item in info:
                self.extract(item,elements,keyword)
        return elements

    ## use feature to determine device
    def featureMethod(self,info):
        self.portCheck(info)
        self.deviceCheck(info)

    def portCheck(self,info):
        ports = info['ports']
        if 515 in ports:
            print(content)
        if 9100 in ports:
            print(content)
        
    def deviceCheck(self,info):
        ports = info['ports']
        for i in range(len(ports)):
            keys = list(info['data'][i].keys())
            for key in keys:
                if key == 'devicetype':
                    devicetype = info['data'][i]['devicetype']
                    if -1 != devicetype.find('router'):
                        print(devicetype)
                    elif -1 != devicetype.find('printer'):
                        print(devicetype)
                    elif -1 != devicetype.find('webcam'):
                        print(devicetype)


if __name__ == "__main__":

    args = process_parser()
    ip = args.ip
    count = args.count

    #run all ports
    if count == -1:
        count = 1000

    API_KEY = "839CrW4f3Omc9wYO9aMWeRq0Go4rEPfN"
    s = shodan_engine(API_KEY,ip,count)
    s.start()
