#!/usr/bin/env python3
"""JWT (JSON Web Token) encode/decode with HMAC-SHA256."""
import sys,json,base64,hashlib,time

def b64url_encode(data):
    if isinstance(data,str):data=data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s):
    s+='='*(4-len(s)%4);return base64.urlsafe_b64decode(s)

def hmac_sha256(key,msg):
    if isinstance(key,str):key=key.encode()
    if isinstance(msg,str):msg=msg.encode()
    bs=64
    if len(key)>bs:key=hashlib.sha256(key).digest()
    key=key.ljust(bs,b'\x00')
    return hashlib.sha256(bytes(k^0x5c for k in key)+hashlib.sha256(bytes(k^0x36 for k in key)+msg).digest()).digest()

def jwt_encode(payload,secret,exp=None):
    header={"alg":"HS256","typ":"JWT"}
    if exp:payload["exp"]=int(time.time())+exp
    parts=b64url_encode(json.dumps(header))+'.'+b64url_encode(json.dumps(payload))
    sig=b64url_encode(hmac_sha256(secret,parts))
    return parts+'.'+sig

def jwt_decode(token,secret,verify=True):
    parts=token.split('.')
    if len(parts)!=3:raise ValueError("Invalid JWT")
    if verify:
        expected=b64url_encode(hmac_sha256(secret,parts[0]+'.'+parts[1]))
        if expected!=parts[2]:raise ValueError("Invalid signature")
    payload=json.loads(b64url_decode(parts[1]))
    if "exp" in payload and payload["exp"]<time.time():raise ValueError("Token expired")
    return payload

def main():
    if len(sys.argv)>1 and sys.argv[1]=="--test":
        token=jwt_encode({"sub":"user123","admin":True},"secret")
        assert token.count('.')==2
        payload=jwt_decode(token,"secret")
        assert payload["sub"]=="user123" and payload["admin"]==True
        # Wrong secret
        try:jwt_decode(token,"wrong");assert False
        except ValueError:pass
        # Tampered token
        parts=token.split('.');parts[1]=b64url_encode('{"sub":"hacker"}')
        try:jwt_decode('.'.join(parts),"secret");assert False
        except ValueError:pass
        print("All tests passed!")
    else:
        token=jwt_encode({"user":"rogue","role":"admin"},"my-secret",exp=3600)
        print(f"JWT: {token[:50]}...")
        print(f"Decoded: {jwt_decode(token,'my-secret')}")
if __name__=="__main__":main()
