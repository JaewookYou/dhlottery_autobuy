#-*- coding: utf-8 -*-
import sys
import urllib
import time
import smtplib
import re
import datetime
import json, hashlib, os
from arang import *
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from email.mime.text import MIMEText
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def pad(m):
    return m+chr(16-len(m)%16)*(16-len(m)%16)

def deriveKey(passphrase: str, salt: bytes=None) -> [str, bytes]:
    if salt is None:
        salt = os.urandom(32)
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), salt, 1000,)[:16], salt

def encrypt(passphrase: str, plaintext: str) -> str:
    global salt, iv
    key, salt = deriveKey(passphrase,salt=salt)
    aes1 = AES.new(key, AES.MODE_CBC, iv)
    plaintext = pad(plaintext).encode("utf8")
    ciphertext = b64encode(aes1.encrypt(plaintext))
    return "%s%s%s" % (hexlify(salt).decode("utf8"), hexlify(iv).decode("utf8"), ciphertext.decode())

def decrypt(passphrase: str, ciphertext: str) -> str:
    global salt, iv
    key, _ = deriveKey(passphrase, salt)
    aes1 = AES.new(key, AES.MODE_CBC, iv)
    plaintext = aes1.decrypt(ciphertext)
    return plaintext

def dec(key, content):
    global salt, iv
    q = json.loads(content.strip().decode('cp949'))['q']
    t = urldecode(urldecode(q))
    salt = hexdecode(t[0:64].encode())
    iv = hexdecode(t[64:96].encode())
    ct = b64decode(t[96:].encode())
    ttt = decrypt(key, ct).split(b'}')[0]+b'}'
    resp = json.loads(ttt)
    return resp

def mailsend(subject, text):
    global mailingList
    smtp = smtplib.SMTP('smtp.gmail.com', 587)
    smtp.ehlo()      # say Hello
    smtp.starttls()  # TLS 사용시 필요
    smtp.login(f"{os.environ['smtpid']}", f"{os.environ['smtppw']}")
    
    for i in mailingList:
        msg = MIMEText(text)
        msg['Subject'] = subject
        msg['To'] = i
        smtp.sendmail(f"{os.environ['smtpid']}", i, msg.as_string())

    smtp.quit()
    print('[+] mail send success')

def get_access_token():
    global proxies, access_token
    print("[+] get kakaotalk access_token")
    refresh_token = os.environ['refresh_token']
    u = "https://kauth.kakao.com/oauth/token"
    data = f"grant_type=refresh_token&client_id={os.environ['kakaokey']}&refresh_token={refresh_token}"
    r = requests.post(u, data=data, allow_redirects=False, proxies=proxies, verify=False)
    apir = json.loads(r.content)
    try:
        if apir["refresh_token"]:
            os.environ['refresh_token'] = apir["refresh_token"]
    except:
        pass
    return apir["access_token"]

def kakaosend(text, simple=True):
    ### 카톡 api auth를 위한것...
    # https://kauth.kakao.com/oauth/authorize?client_id={os.environ['kakaokey']}&redirect_uri=https://ar9ang3.com/kakaoAuth.php&response_type=code&scope=friends,talk_message
    ### 토큰 valid 만료되면 이거 써야함 

    global access_token
    if access_token == '':
        access_token = get_access_token()
       
    headers3={}
    headers3["Authorization"] = "Bearer {}".format(access_token)
    '''
    print("[+] get friends list")
    u= "https://kapi.kakao.com/v1/api/talk/friends"
    r = requests.get(u, headers=headers3, proxies=proxies, verify=False)
    flist = json.loads(r.content)
    uuid = flist["elements"][0]["uuid"]
    '''
    uuid = f"{os.environ['kakaouuid']}"
    headers3["Content-Type"] = "application/x-www-form-urlencoded"
    headers3["Content-Length"] = "123"
    u = "https://kapi.kakao.com/v1/api/talk/friends/message/default/send"
    headers3["Authorization"] = "Bearer {}".format(access_token)
    link = "https://ar9ang3.com/"
    if simple:
        text = ('template_object={"object_type":"text","text":"%s","link":{"web_url":"%s","mobile_web_url":"%s","android_execution_params":"%s","ios_execution_params":"%s"}}' % (text, link, link, link, link)).encode('utf-8')
    data = ('receiver_uuids=["'+uuid+'"]&').encode('utf-8') + text

    r = requests.post(u, data=data, headers=headers3, proxies=proxies, verify=False)
    if r.status_code == 200:
        print("[+] kakao send success!")
    else:
        print("[x] kakao send fail")
        mailsend("[dhlottery] fail..", "[x] kakao send fail")

def charge(curval):
    global headers, s, proxies
    print("[!] value is under 10000, charge process init!")
    amt = 50000
    u="https://www.dhlottery.co.kr/nicePay.do?method=nicePayInit"
    data=u"PayMethod=VBANKFVB01&VbankBankCode=089&price={}&goodsName=복권예치금&vExp={}".format(amt,datetime.datetime.today().strftime("%Y%m%d")).encode("utf-8")
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["Content-Length"] = "153"

    r = s.post(u,data=data,headers=headers,proxies=proxies,verify=False)
    a=json.loads(r.content.decode("euc-kr"))
    
    u="https://www.dhlottery.co.kr/nicePay.do?method=nicePayProcess"
    data=f'PayMethod=VBANKFVB01&GoodsName=%BA%B9%B1%C7%BF%B9%C4%A1%B1%DD&GoodsCnt=1&BuyerTel={os.environ["buyertel"]}&Moid={a["Moid"]}&MID={a["MID"]}&UserIP={a["UserIP"]}&MallIP={a["MallIP"]}&MallUserID={os.environ["dhid"]}&VbankExpDate={a["VbankExpDate"]}&BuyerEmail={os.environ["buyeremail"]}&SocketYN=Y&GoodsCl=0&TransType=0&OptionList=no_receipt&EncodeParameters=CardNo%2CCardExpire%2CCardPwd&EdiDate={a["EdiDate"]}&EncryptData={a["EncryptData"]}&TrKey=&VbankBankCode=089&VbankNum={os.environ["kbankacctno"]}&FxVrAccountNo={os.environ["kbankacctno"]}&VBankAccountName={os.environ["buyername"]}&Amt={amt}&BuyerName={os.environ["buyername"]}'
    try:
        r = s.post(u,data=data,headers=headers,proxies=proxies,verify=False)
    except:
        print("[x] charge request err...")
        kakaosend("[dhlottery] charge request fail")
        exit(1)
    
    print("[+] charge request success!")
    
    u="https://toss.im/transfer-web/linkgen-api/link"
    headers2 = {"Content-Type":"application/json","Content-Length":"142"}
    body = {
    "apiKey":f"{os.environ['tosskey']}",
    "bankName":"케이뱅크",
    "bankAccountNo":a["FxVrAccountNo"],
    "amount":int(a["amt"]),
    "message":f"{os.environ['username']}"
    }
    try:
        r = s.post(u,data=json.dumps(body), headers=headers2, proxies=proxies, verify=False)
        deeplink = json.loads(r.content)["success"]["scheme"] 
        deepurl = json.loads(r.content)["success"]["link"]       
    except:
        print("[x] deeplink create fail ...")
        kakaosend("[dhlottery] deeplink create fail...")
        exit(1)
    print("[+] deeplink create success!")
    txt = '''동행복권 충전
    
    현재금액 : {}
    입금액 : {}
    입금후 금액 : {}
    링크 : {}'''.format(curval, a["amt"], str(curval+int(a["amt"])), deeplink)
    
    text = (u'template_object={"object_type":"text","text":"%s","link":{"web_url":"%s","mobile_web_url":"%s","android_execution_params":"%s","ios_execution_params":"%s"},"button_title":"이동테스트","buttons":[{"title":"이체하기","link":{"web_url":"%s","mobile_web_url":"%s","android_execution_params":"%s","ios_execution_params":"%s"}}]}' % (txt.replace("\n","\\n").replace("&","%26"),deepurl,deepurl,deepurl,deepurl,deepurl,deepurl,deepurl,deepurl)).encode('utf-8')
    
    kakaosend(text,simple=False)

#global vars
access_token=''
mailingList = [f"{os.environ['smtptoid']}"]
headers = {
'Connection': 'keep-alive',
'Upgrade-Insecure-Requests': '1',
'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
'Sec-Fetch-Site': 'same-origin',
'Sec-Fetch-Mode': 'navigate',
'Sec-Fetch-Dest': 'document',
'Referer': 'https://www.dhlottery.co.kr/user.do?method=login&returnUrl=',
'Accept-Encoding': 'gzip, deflate, br',
'Content-Type': 'application/x-www-form-urlencoded',
'Content-Length': '155',
'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
'Cookie': f'WMONID=NVtsRlPYnZZ; userId={os.environ["dhid"]}; UID={os.environ["dhid"]}; JSESSIONID=KigpbHXFtVNEYav9eU0RFmEo1b9uOKzt9W6VjB6GagYZPaQ4VmqTf3a5wi8lALly.cG9ydGFsX2RvbWFpbi9lbGQ0;'
}

proxies={"https":"192.168.20.17:8888","http":"192.168.20.17:8888"}

#'''
u="https://www.dhlottery.co.kr/userSsl.do?method=login"
data=f"returnUrl=&newsEventYn=&userId={os.environ['dhid']}&password={os.environ['dhpw']}&checkSave=on"
s = requests.session()

h = headers

r = s.post(u,data=data,headers=h,proxies=proxies,allow_redirects=False,verify=False)
t = headers['Cookie']
headers['Cookie'] = re.sub("JSESSIONID=[\w\.=]+;","JSESSIONID="+r.headers['Set-Cookie'].split('JSESSIONID=')[1].split(';')[0]+";",headers['Cookie'])
jsession = r.headers['Set-Cookie'].split('JSESSIONID=')[1].split(';')[0]
if t == headers['Cookie']:
    print("[x] login fail...")
    kakaosend("[dhlottery] [x] login fail...")
headers['Cookie'] = headers['Cookie'] + "; Domain=.dhlottery.co.kr;"

print("[!] login success!")

del headers['Content-Type']
del headers['Content-Length']



u="https://www.dhlottery.co.kr/userSsl.do?method=myPage"
r = s.get(u,headers=headers,proxies=proxies,verify=False)
curval = int(r.content.split(b'<a href="/myPage.do?method=depositListView"><strong>')[1].split(u'원'.encode('euc-kr'))[0].replace(b',',b''))
#'''

if curval < 10000:
    charge(curval)    
    del headers['Content-Type']
    del headers['Content-Length']

iv = bytes.fromhex("1bc6ed0ad5bac01dd0b2543d84296f02")
salt = bytes.fromhex("08aecf24f96c32942de7d7b81bd0b39ef153498e5de5776e5e43e3e5c0d0c986")
key = jsession[:32]

u = "https://el.dhlottery.co.kr/game/pension720/process/roundRemainTime.jsp?ROUND=&SEL_NO=&BUY_CNT=&AUTO_SEL_SET=&SEL_CLASS=&BUY_TYPE=A&ACCS_TYPE=01"
r = json.loads(s.get(u, headers=headers, proxies=proxies, verify=False).content.strip().decode('cp949'))
roundNum = r["ROUND"]
CLOSE_DATE = r["CLOSE_DATE"]
print(f"[+] round - {roundNum}")

# get rnd num
u = "https://el.dhlottery.co.kr/game/pension720/process/makeAutoNo.jsp"
plain = f"ROUND={roundNum}&SEL_NO=&BUY_CNT=&AUTO_SEL_SET=SA&SEL_CLASS=&BUY_TYPE=A&ACCS_TYPE=01"

t = encrypt(key, plain)
headers['Content-Type'] = 'application/x-www-form-urlencoded'
headers['Content-Length'] = '123'
data = "q={}".format(urlencode(urlencode(t)))

r = s.post(u, data=data, headers=headers, proxies=proxies, verify=False)
dq = dec(key, r.content)
roundNum = dq['round']
selLotNo = dq['selLotNo']
print(f'[+] round - {roundNum} , random - {selLotNo}')

# buy lottery - step 1
u = "https://el.dhlottery.co.kr/game/pension720/process/makeOrderNo.jsp"
plain = f"ROUND={roundNum}&SEL_NO={selLotNo}&BUY_CNT=5&AUTO_SEL_SET=SA&SEL_CLASS=&BUY_TYPE=A&ACCS_TYPE=01"
t = encrypt(key, plain)
data = "q={}".format(urlencode(urlencode(t)))

r = s.post(u, data=data, headers=headers, proxies=proxies, verify=False)
resp = dec(key, r.content)

orderNo = resp['orderNo']
orderDate = resp['orderDate']

# buy lottery - step 2
plain = f'ROUND={roundNum}&FLAG=&BUY_KIND=01&BUY_NO=1{selLotNo}%2C2{selLotNo}%2C3{selLotNo}%2C4{selLotNo}%2C5{selLotNo}&BUY_CNT=5&BUY_SET_TYPE=SA%2CSA%2CSA%2CSA%2CSA&BUY_TYPE=A%2CA%2CA%2CA%2CA&ACCS_TYPE=01&orderNo={orderNo}&orderDate={orderDate}&TRANSACTION_ID=&WIN_DATE=&USER_ID={os.environ["dhid"]}&PAY_TYPE=&resultErrorCode=&resultErrorMsg=&resultOrderNo=&WORKING_FLAG=true&NUM_CHANGE_TYPE=&auto_process=N&set_type=SA&classnum=&selnum=&buytype=M&num1=&num2=&num3=&num4=&num5=&num6=&DSEC=30&CLOSE_DATE={CLOSE_DATE}&verifyYN=N&curdeposit={curval}&curpay=5000&DROUND={roundNum}&DSEC=0&CLOSE_DATE=&verifyYN=N&lotto720_radio_group=on'

u = "https://el.dhlottery.co.kr/game/pension720/process/connPro.jsp"
t = encrypt(key, plain)
data = "q={}".format(urlencode(urlencode(t)))
r = s.post(u, data=data, headers=headers, proxies=proxies, verify=False)
resp = dec(key, r.content)
print(resp)

if int(resp["failCnt"]) > 0:
    print("[x] pension lotto buy fail")
    kakaosend(f"[dhlottery] pension lotto buy fail\\n{resp['saleTicket']}")
else:
    print("[+] pension lotto buy success!")
    kakaosend("[dhlottery] pension lotto buy success")

# lotto buy
u="https://ol.dhlottery.co.kr/olotto/game/game645.do"
r = s.get(u, proxies=proxies, verify=False)
if len(r.content) > 0:
    roundNum = r.content.split(b'curRound">')[1].split(b'<')[0].decode()
    ROUND_DRAW_DATE = r.content.split(b'ROUND_DRAW_DATE" value="')[1].split(b'"')[0].decode()
    WAMT_PAY_TLMT_END_DT = r.content.split(b'WAMT_PAY_TLMT_END_DT" value="')[1].split(b'"')[0].decode()
else:
    print('[x] lotto round get fail')
    kakaosend("[dhlottery] lotto round get fail fail")
    
lottoParam = f'round={roundNum}&direct=172.17.20.52&nBuyAmount=5000&param=%5B%7B%22genType%22%3A%220%22%2C%22arrGameChoiceNum%22%3Anull%2C%22alpabet%22%3A%22A%22%7D%2C%7B%22genType%22%3A%220%22%2C%22arrGameChoiceNum%22%3Anull%2C%22alpabet%22%3A%22B%22%7D%2C%7B%22genType%22%3A%220%22%2C%22arrGameChoiceNum%22%3Anull%2C%22alpabet%22%3A%22C%22%7D%2C%7B%22genType%22%3A%220%22%2C%22arrGameChoiceNum%22%3Anull%2C%22alpabet%22%3A%22D%22%7D%2C%7B%22genType%22%3A%220%22%2C%22arrGameChoiceNum%22%3Anull%2C%22alpabet%22%3A%22E%22%7D%5D&ROUND_DRAW_DATE={ROUND_DRAW_DATE}&WAMT_PAY_TLMT_END_DT={WAMT_PAY_TLMT_END_DT}&gameCnt=5'

u = "https://ol.dhlottery.co.kr/olotto/game/execBuy.do"

r = s.post(u, data=lottoParam, headers=headers, proxies=proxies, verify=False)
resp = json.loads(r.content.decode('utf-8'))
print(resp)
if resp["result"]["resultMsg"] != "SUCCESS":
    print("[x] err. lotto buy fail")
    kakaosend(f'[dhlottery] lotto buy fail\\n{resp["result"]["resultMsg"]}')
else:
    kakaosend("[dhlottery] lotto645 buy success!")
    kakaosend(','.join(resp["result"]["arrGameChoiceNum"]))

if curval - 10000 < 10000:
    charge(curval-10000)