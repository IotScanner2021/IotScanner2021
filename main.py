import sys
from shod import shodan_engine
from cens import censys_engine
from zoom import zoomeye_engine
from parser import process_parser

if __name__ == "__main__":
    
    ## args prepare
    args = process_parser()
    ip = args.ip
    count = args.count
    
    #run all ports
    if count == -1:
        count = 1000

    api_key = "839CrW4f3Omc9wYO9aMWeRq0Go4rEPfN"
    s = shodan_engine(api_key,ip,count)  
    s.start()

    api_key = "7557767C-20cf-fd7d5-d848-d7a5904e8f1" 
    z = zoomeye_engine(api_key,ip,count)
    z.start()

    api = dict()
    api['id'] = "440fac81-e807-4300-bcd7-92023c449af2"
    api['secret'] = "Dq84v4A9ryFmHqiIFJHMFN1MECcqV2fx"
    api['ip'] = ip
    api['count'] = count

    c = censys_engine(api)
    c.start()
