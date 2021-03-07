import shodan
import json
import sys
from time import sleep
from parser import process_parser


def portCheck(info):
    ports = info['ports']
    if 515 in ports:
        content = str(info['ip_str']) + ":port 515 printer find"
        writeToFile('log/port.log',content)
        print(content)
    if 9100 in ports:
        content = str(info['ip_str']) + ':port 9100 printer find'
        writeToFile('log/port.log',content)
        print(content)

## save in log directory
def deviceCheck(info):
    ports = info['ports']
    for i in range(len(ports)):
        keys = list(info['data'][i].keys())
        for key in keys:
            if key == 'devicetype':
                devicetype = info['data'][i]['devicetype']
                content = str(info['data'][i]['port']) + ":" + devicetype
                writeToFile("log/devicetype.log",content)
                if -1 != devicetype.find('router'):
                    writeToFile("log/router.log",content)
                elif -1 != devicetype.find('printer'):
                    writeToFile('log/printer.log',content)
                elif -1 != devicetype.find('webcam'):
                    writeToFile('log/webcam.log',content)
                print(content)

def writeToFile(name,content):
    f = open(name,"a+")
    f.write(content)
    f.close()

def json_output(info):
    j = json.dumps(info,indent=4)
    print(j)

def shodan_engine(api_key,ip,count):
    api = shodan.Shodan(api_key)
    
    # search only 1 ip
    if count == 1:
        info = api.host(ip)
        json_output(info)
        portCheck(info)
        deviceCheck(info)
        return

    mask = ip.split('/')[1]

    if mask == "16":
        ip_str = "".join([ip.split('.')[0],".",ip.split('.')[1]])

        for i in range (0 , 256 , 1):
            for j in range (0 , 256 , 1):
                if j == count:
                    return
                
                ip = ip_str + "." + str(i) + "." + str(j)
                try:
                    info = api.host(ip)
                    content = "ip:" + str(info['ip_str'])
                    writeToFile("log/running.log",content)
                    portCheck(info)
                    deviceCheck(info)
                    sleep(1.5)

                except shodan.APIError as e:
                    print(e)
                    continue

if __name__ == "__main__":
   
    args = process_parser()
    ip = args.ip
    count = args.count

    if count == -1:
        count == 1000

    API_KEY = "839CrW4f3Omc9wYO9aMWeRq0Go4rEPfN" 
    shodan_engine(API_KEY,ip,count);
    print("finish!!!")
