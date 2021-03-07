import sys
from zoomeye.sdk import ZoomEye
from parser import process_parser

def format(dataum):
    
    if dataum['portinfo']['os'] != '':
        os = dataum['portinfo']['os']
    else: 
        os = 'None'
    
    print("ip:" + dataum['ip'], end = '\t')
    print("os:" + os, end = '\t')
    print("port:" + str(dataum['portinfo']['port']))

def zoomeye_engine(api_key,ip,count):
    zm = ZoomEye(api_key=api_key) #API-KEY for 認證
    pattern = "cidr:" + ip
    data = zm.dork_search(pattern)
    #print(data)

    num = 1
    for datum in data:
        if(num > count):
            return
        format(datum)
        num += 1

if __name__ == "__main__":

    args = process_parser()
    ip = args.ip
    count = args.count

    API_KEY = "7557767C-20cf-fd7d5-d848-d7a5904e8f1" 
    zoomeye_engine(API_KEY,ip,count)
