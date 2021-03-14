import requests
from bs4 import BeautifulSoup as bs

'''
Steps
1. go into Vendor-search
2. get CWE,product,CVE 
3. go into CVE
4. get all CVE
'''

def findHrefs(find,text):
    links = text.findAll('a')
    
    hrefs = []
    for link in links:
        href = link.get('href')
        if href != None:
            hrefLower = href.lower()
            if find in hrefLower:
                hrefs.append(href)

    return hrefs

def vendorFindCve(vendor):

    ### go into vendor search & get CWE,product,CVE
    params = {"search":vendor}
    url = "https://www.cvedetails.com/vendor-search.php"
    res = requests.get(url,params)
    text = bs(res.text,'html.parser')

    vulnUrls = findHrefs(vendor,text)

    ### go into CVE & get all CVE

    vulnUrl = "https://www.cvedetails.com" + vulnUrls[2]
    
    res = requests.get(vulnUrl)
    text = bs(res.text,'html.parser')

    cveUrls = findHrefs("/cve/",text)
    for cveUrl in cveUrls:
        cve = cveUrl.split('/')
        print(cve[2])

if __name__ == "__main__":

    vendor = input("Input vendor:")
    info = vendorFindCve(vendor)
