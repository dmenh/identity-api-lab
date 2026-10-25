"""Identity API Lab by Dinesh. Copyright 2026 Dinesh. All rights reserved."""
import os, json, uuid, secrets, hashlib, hmac, time, re, base64, urllib.request, urllib.error, ipaddress, socket, csv, io
from concurrent import futures
from types import SimpleNamespace
from datetime import datetime, timezone, timedelta
from pathlib import Path
from contextlib import asynccontextmanager
from urllib.parse import parse_qs, urlencode, urlparse
from decimal import Decimal, InvalidOperation
from xml.etree.ElementTree import Element, SubElement, tostring
from defusedxml.ElementTree import fromstring
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from sqlalchemy import create_engine, String, Text, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.exc import IntegrityError
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi
from graphql import build_schema, graphql_sync, GraphQLError, parse as graphql_parse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import grpc
import paramiko
from google.protobuf.struct_pb2 import Struct
from google.protobuf.json_format import MessageToDict, ParseDict

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./data/lab.db')
if DATABASE_URL.startswith('sqlite:///'):
    Path(DATABASE_URL[10:]).parent.mkdir(parents=True, exist_ok=True)
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread':False} if DATABASE_URL.startswith('sqlite') else {}, pool_pre_ping=True)
Session = sessionmaker(engine)
class Base(DeclarativeBase): pass
class Record(Base):
    __tablename__ = 'lab_records'
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    body: Mapped[str] = mapped_column(Text)
ph = PasswordHasher()
def now(): return datetime.now(timezone.utc).isoformat()
def uid(): return str(uuid.uuid4())
def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def rows(db, kind): return [json.loads(x.body) for x in db.scalars(select(Record).where(Record.kind==kind))]
def get(db, kind, key):
    r=db.get(Record,kind+':'+str(key)); return json.loads(r.body) if r else None
def save(db,kind,obj):
    key=kind+':'+obj['id']; r=db.get(Record,key)
    if r: r.body=json.dumps(obj)
    else: db.add(Record(key=key,kind=kind,body=json.dumps(obj)))
    db.flush(); return obj
def required(db,kind,key):
    x=get(db,kind,key)
    if not x: raise HTTPException(404,kind+' not found')
    return x

CATALOG=['CUSTOMER_READ','ACCOUNT_READ','TRANSACTION_READ','TRANSACTION_CREATE','TRANSACTION_APPROVE','USER_CREATE','USER_UPDATE','USER_STATUS_MANAGE','USER_PASSWORD_RESET','ACCESS_MANAGE','API_MANAGE','CLIENT_MANAGE','SESSION_REVOKE','AUDIT_READ','SYSTEM_CONFIGURE']
SCOPES=['users:read','users:write','roles:read','roles:write','groups:read','groups:write','banking:read','banking:write']
AUTH_METHODS=['oauth2_client_credentials','oauth2_authorization_code_pkce','api_key','http_basic','jwt_bearer','hmac_sha256','http_digest']
READABLE_USER_ATTRIBUTES=['username','displayName','firstName','lastName','email','department','jobTitle','country','city','active','locked','deleted','passwordResetRequired','roles','groups','permissions','createdAt','updatedAt']
WRITABLE_USER_ATTRIBUTES=['username','password','displayName','firstName','lastName','email','department','jobTitle','country','city','active','locked','deleted','passwordResetRequired','roles','groups']
SERVER_KEY=os.getenv('SERVER_SIGNING_KEY',os.getenv('ADMIN_PASSWORD','identity-api-lab-local-signing-key')).encode()
REALM='Identity API Lab'
NONCES={}
def encrypt_secret(value):
    if not value: return None
    nonce=secrets.token_bytes(12); key=hashlib.sha256(SERVER_KEY+b':sso-config').digest(); return b64url(nonce+AESGCM(key).encrypt(nonce,value.encode(),b'identity-api-lab-sso'))
def decrypt_secret(value):
    if not value: return ''
    raw=b64decode(value); key=hashlib.sha256(SERVER_KEY+b':sso-config').digest(); return AESGCM(key).decrypt(raw[:12],raw[12:],b'identity-api-lab-sso').decode()
def safe_sso_url(value,resolve=False):
    value=str(value or '').rstrip('/')
    parsed=urlparse(value); insecure=os.getenv('ALLOW_INSECURE_SSO','false').lower()=='true'; private=os.getenv('ALLOW_PRIVATE_SSO','false').lower()=='true'
    if parsed.scheme not in (('https','http') if insecure else ('https',)) or not parsed.hostname or parsed.username or parsed.password: raise HTTPException(400,'SSO endpoints must use an absolute HTTPS URL without embedded credentials')
    if not private:
        if parsed.hostname.lower() in ('localhost','localhost.localdomain') or parsed.hostname.lower().endswith(('.local','.internal')): raise HTTPException(400,'Private SSO endpoints require ALLOW_PRIVATE_SSO=true')
        try:
            addresses=[ipaddress.ip_address(parsed.hostname)] if re.fullmatch(r'[0-9a-fA-F:.]+',parsed.hostname) else ([ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(parsed.hostname,parsed.port or 443,type=socket.SOCK_STREAM)] if resolve else [])
            if any(x.is_private or x.is_loopback or x.is_link_local or x.is_multicast or x.is_reserved or x.is_unspecified for x in addresses): raise HTTPException(400,'Private SSO endpoints require ALLOW_PRIVATE_SSO=true')
        except HTTPException: raise
        except ValueError: raise HTTPException(400,'Invalid SSO endpoint address')
        except socket.gaierror as exc: raise HTTPException(502,'Identity provider hostname could not be resolved') from exc
    return value
def remote_json(url,data=None,headers=None):
    request=urllib.request.Request(safe_sso_url(url,resolve=True),data=urlencode(data).encode() if data else None,headers=headers or {})
    try:
        with urllib.request.urlopen(request,timeout=10) as response: return json.loads(response.read(1048576))
    except Exception as exc: raise HTTPException(502,'Identity provider request failed') from exc
def validate_id_token(value,provider,expected_nonce):
    try:
        head,payload,signature=value.split('.'); header=json.loads(b64decode(head)); claims=json.loads(b64decode(payload))
        if header.get('alg')!='RS256': raise ValueError('Only RS256 ID tokens are accepted')
        jwks=remote_json(provider['jwksUri']); key=next(x for x in jwks.get('keys',[]) if x.get('kid')==header.get('kid'))
        public=rsa.RSAPublicNumbers(int.from_bytes(b64decode(key['e']),'big'),int.from_bytes(b64decode(key['n']),'big')).public_key(); public.verify(b64decode(signature),(head+'.'+payload).encode(),padding.PKCS1v15(),hashes.SHA256())
        audience=claims.get('aud',[]); audience=[audience] if isinstance(audience,str) else audience
        if claims.get('iss','').rstrip('/')!=provider['issuer'].rstrip('/') or provider['clientId'] not in audience or claims.get('exp',0)<time.time() or not secrets.compare_digest(str(claims.get('nonce','')),expected_nonce): raise ValueError('Invalid ID token claims')
        return claims
    except HTTPException: raise
    except Exception as exc: raise HTTPException(401,'Invalid identity provider ID token') from exc
def b64url(value): return base64.urlsafe_b64encode(value).decode().rstrip('=')
def b64decode(value): return base64.urlsafe_b64decode(value+'='*((4-len(value)%4)%4))
def derived_secret(client,purpose): return b64url(hmac.new(SERVER_KEY,(purpose+':'+client['id']+':'+str(client.get('credentialVersion',1))).encode(),hashlib.sha256).digest())
def jwt_token(client,scopes):
    header=b64url(json.dumps({'alg':'HS256','typ':'JWT'},separators=(',',':')).encode()); payload=b64url(json.dumps({'iss':'identity-api-lab','sub':client['id'],'aud':'identity-api-lab-api','scope':' '.join(scopes),'iat':int(time.time()),'exp':int(time.time())+3600,'jti':uid(),'ver':client.get('credentialVersion',1)},separators=(',',':')).encode()); signature=b64url(hmac.new(SERVER_KEY,(header+'.'+payload).encode(),hashlib.sha256).digest()); return header+'.'+payload+'.'+signature
def verify_jwt(value):
    try:
        head,payload,signature=value.split('.'); expected=b64url(hmac.new(SERVER_KEY,(head+'.'+payload).encode(),hashlib.sha256).digest())
        if not secrets.compare_digest(signature,expected): return None
        claims=json.loads(b64decode(payload)); return claims if claims.get('iss')=='identity-api-lab' and claims.get('aud')=='identity-api-lab-api' and claims.get('exp',0)>time.time() else None
    except Exception: return None
def digest_nonce():
    stamp=str(int(time.time())); return b64url((stamp+':'+hmac.new(SERVER_KEY,stamp.encode(),hashlib.sha256).hexdigest()).encode())
def valid_digest_nonce(value):
    try:
        stamp,signature=b64decode(value).decode().split(':',1); return abs(time.time()-int(stamp))<300 and secrets.compare_digest(signature,hmac.new(SERVER_KEY,stamp.encode(),hashlib.sha256).hexdigest())
    except Exception: return False
ROLE_DEFS=[('viewer','Viewer',CATALOG[:3]),('customer-service','Customer Service Representative',['CUSTOMER_READ','ACCOUNT_READ']),('teller','Teller',CATALOG[:4]),('operator','Transaction Operator',CATALOG[:4]),('approver','Transaction Approver',CATALOG[:3]+['TRANSACTION_APPROVE']),('branch-manager','Branch Manager',CATALOG[:5]),('user-admin','User Administrator',CATALOG[5:10]),('security-admin','Security Administrator',['ACCESS_MANAGE','SESSION_REVOKE','AUDIT_READ','USER_STATUS_MANAGE']),('api-admin','API Administrator',['API_MANAGE','CLIENT_MANAGE','AUDIT_READ']),('super-admin','Super Administrator',CATALOG)]
PROTOCOLS=[('rest','REST / JSON','/api/v1','Versioned identity resources'),('scim','SCIM 2.0','/scim/v2','RFC 7644 Users and Groups'),('scim11','SCIM 1.1','/scim/v1','Legacy SCIM User compatibility'),('soap11','SOAP 1.1','/soap','XML envelope and WSDL'),('soap12','SOAP 1.2','/soap','XML envelope and WSDL'),('graphql','GraphQL','/graphql','Typed schema, queries and mutations'),('odata','OData 4.0','/odata/v4','Entity sets, metadata and query options'),('grpc','gRPC','localhost:50051','Native protobuf RPC identity service'),('jsonrpc','JSON-RPC 2.0','/jsonrpc','Batch-safe identity RPC methods'),('webhooks','Webhooks','/admin-api/webhooks','Signed lifecycle event delivery'),('csvsftp','CSV / SFTP','/api/v1/csv/users','CSV exchange and managed SFTP transfer')]
def effective(db,u):
    perms=set(); roleids=set(u.get('roles',[]))
    for g in rows(db,'group'):
        if u['id'] in g.get('members',[]): roleids.update(g.get('roles',[])); perms.update(g.get('permissions',[]))
    for rid in roleids:
        r=get(db,'role',rid)
        if r: perms.update(r['permissions'])
    return sorted(perms)
def public_user(db,u):
    return {**{k:v for k,v in u.items() if k not in ('passwordHash','failedLogins')},'permissions':effective(db,u),'groups':[g['id'] for g in rows(db,'group') if u['id'] in g.get('members',[])]}
def api_user(req,db,u):
    result=public_user(db,u); client=getattr(req.state,'apiClient',None)
    if not client: return result
    readable=set(client.get('readAttributes',READABLE_USER_ATTRIBUTES))
    return {k:v for k,v in result.items() if k=='id' or k in readable}
def enforce_write_attributes(req,data):
    client=getattr(req.state,'apiClient',None)
    if not client: return
    allowed=set(client.get('writeAttributes',WRITABLE_USER_ATTRIBUTES)); attempted=set(data).intersection(WRITABLE_USER_ATTRIBUTES); denied=sorted(attempted-allowed)
    if denied: raise HTTPException(403,'Client cannot write user attributes: '+', '.join(denied))
def require_read_attribute(req,attribute):
    client=getattr(req.state,'apiClient',None)
    if client and attribute not in client.get('readAttributes',READABLE_USER_ATTRIBUTES): raise HTTPException(403,'Client cannot read user attribute: '+attribute)
def attribute_policy(data):
    readable=data.get('readAttributes',READABLE_USER_ATTRIBUTES); writable=data.get('writeAttributes',WRITABLE_USER_ATTRIBUTES)
    if not isinstance(readable,list) or len(readable)!=len(set(readable)) or any(x not in READABLE_USER_ATTRIBUTES for x in readable): raise HTTPException(400,'Unknown or duplicate readable user attribute')
    if not isinstance(writable,list) or len(writable)!=len(set(writable)) or any(x not in WRITABLE_USER_ATTRIBUTES for x in writable): raise HTTPException(400,'Unknown or duplicate writable user attribute')
    return readable,writable
def seed_banking_activity(db):
    accounts=rows(db,'account'); users=rows(db,'user')
    if len(accounts)<4 or not users: return
    by_name={u['username']:u for u in users}; stamp=now()
    samples=[
        ('transaction-demo-1','account-1','account-2','420.00','Supplier settlement','liam.johnson','yuki.tanaka'),
        ('transaction-demo-2','account-3','account-4','1875.50','Monthly services','isabella.silva','wei.chen'),
        ('transaction-demo-3','account-5','account-6','235.75','Research subscription','liam.johnson','yuki.tanaka'),
        ('transaction-demo-4','account-2','account-5','9200.00','Equipment purchase','isabella.silva','wei.chen')]
    for tid,source,dest,amount,reference,maker,checker in samples:
        if not get(db,'transaction',tid): save(db,'transaction',dict(id=tid,paymentId='historical-'+tid,fromAccountId=source,toAccountId=dest,amount=amount,currency='USD',reference=reference,status='Completed',createdBy=by_name.get(maker,{}).get('id'),createdByName=by_name.get(maker,{}).get('displayName',maker),approvedBy=by_name.get(checker,{}).get('id'),approvedByName=by_name.get(checker,{}).get('displayName',checker),createdAt=stamp,approvedAt=stamp,completedAt=stamp))
    pending=[('payment-demo-1','account-1','account-3','750.00','Vendor invoice INV-2048','liam.johnson','yuki.tanaka','Standard review'),('payment-demo-2','account-4','account-6','12500.00','Treasury allocation','isabella.silva','wei.chen','Enhanced review')]
    for pid,source,dest,amount,reference,maker,checker,tier in pending:
        if not get(db,'payment',pid):
            creator=by_name.get(maker,{}); approver=by_name.get(checker,{})
            save(db,'payment',dict(id=pid,fromAccountId=source,toAccountId=dest,amount=amount,currency='USD',reference=reference,status='Pending',approvalTier=tier,createdBy=creator.get('id'),createdByName=creator.get('displayName',maker),assignedApproverId=approver.get('id'),assignedApproverName=approver.get('displayName',checker),createdAt=stamp,approvalHistory=[{'action':'Submitted','actor':creator.get('displayName',maker),'timestamp':stamp},{'action':'Assigned','actor':'Workflow engine','detail':approver.get('displayName',checker),'timestamp':stamp}]))
def seed():
    Base.metadata.create_all(engine)
    with Session.begin() as db:
        for rid,name,perms in ROLE_DEFS:
            if not get(db,'role',rid): save(db,'role',{'id':rid,'name':name,'description':name+' access profile','permissions':perms})
        for pid,name,endpoint,description in PROTOCOLS:
            if not get(db,'protocol',pid): save(db,'protocol',dict(id=pid,name=name,endpoint=endpoint,description=description,status='Implemented',enabled=True))
        if rows(db,'user'):
            for u in rows(db,'user'):
                if not get(db,'username',digest(u['username'].lower())): save(db,'username',{'id':digest(u['username'].lower()),'userId':u['id']})
            seed_banking_activity(db); return
        people=[('admin','Dinesh','Administrator','Kenya','Nairobi','Technology','Platform Administrator','super-admin'),('emma.wilson','Emma','Wilson','United Kingdom','London','Retail Banking','Branch Manager','branch-manager'),('liam.johnson','Liam','Johnson','United States','New York','Payments','Transaction Operator','operator'),('yuki.tanaka','Yuki','Tanaka','Japan','Tokyo','Risk & Compliance','Transaction Approver','approver'),('priya.sharma','Priya','Sharma','India','Mumbai','Customer Experience','Customer Service Lead','customer-service'),('lucas.martin','Lucas','Martin','France','Paris','Retail Banking','Teller','teller'),('sofia.muller','Sofia','Muller','Germany','Berlin','Security','Security Administrator','security-admin'),('oliver.brown','Oliver','Brown','Australia','Sydney','Technology','API Engineer','api-admin'),('amina.hassan','Amina','Hassan','United Arab Emirates','Dubai','Operations','User Administrator','user-admin'),('wei.chen','Wei','Chen','Singapore','Singapore','Treasury','Transaction Approver','approver'),('isabella.silva','Isabella','Silva','Brazil','Sao Paulo','Payments','Transaction Operator','operator'),('noah.williams','Noah','Williams','Canada','Toronto','Audit','Analyst','viewer'),('thandi.nkosi','Thandi','Nkosi','South Africa','Cape Town','Retail Banking','Branch Manager','branch-manager'),('mateo.garcia','Mateo','Garcia','Spain','Madrid','Customer Experience','Relationship Officer','customer-service'),('jiwoo.kim','Jiwoo','Kim','South Korea','Seoul','Technology','Integration Analyst','viewer')]
        password=ph.hash(os.getenv('DEMO_PASSWORD','Lab-Demo-2026!'))
        for login,first,last,country,city,dept,title,role in people:
            save(db,'user',dict(id=uid(),username=login,firstName=first,lastName=last,displayName=first+' '+last,email=login+'@example.test',country=country,city=city,department=dept,jobTitle=title,active=True,locked=False,deleted=False,passwordResetRequired=False,roles=[role],passwordHash=ph.hash(os.getenv('ADMIN_PASSWORD','Lab-Demo-2026!')) if login=='admin' else password,failedLogins=0,createdAt=now(),updatedAt=now()))
        for u in rows(db,'user'): save(db,'username',{'id':digest(u['username'].lower()),'userId':u['id']})
        for i,(dept,role) in enumerate([('Retail Banking','viewer'),('Payments','operator'),('Technology','viewer')]):
            save(db,'group',dict(id='group-'+str(i+1),displayName=dept,roles=[role],permissions=[],members=[u['id'] for u in rows(db,'user') if u['department']==dept]))
        for i,name in enumerate(['Acacia Trading','Harbor Studios','Maple Logistics','Sakura Design','Atlas Research','Cedar Foods']):
            cid='customer-'+str(i+1); save(db,'customer',dict(id=cid,name=name,email='contact'+str(i+1)+'@example.test',country=people[i+1][3],status='Active',segment='Business'))
            save(db,'account',dict(id='account-'+str(i+1),customerId=cid,customerName=name,number='SIM-'+str(10002001+i),currency='USD',balance='25000.00',status='Active',type='Business checking'))
        seed_banking_activity(db)

def grpc_request(context):
    metadata={x.key:x.value for x in context.invocation_metadata()}
    state=SimpleNamespace(correlationId=uid(),actor='anonymous',authentication='none',decision='pending',userId=None)
    return SimpleNamespace(headers={'authorization':metadata.get('authorization','')},cookies={},state=state,url=SimpleNamespace(path='/grpc'),method='POST')
def grpc_struct(value):
    message=Struct(); ParseDict(value,message); return message
def grpc_call(name,write,callback):
    def invoke(message,context):
        started=time.perf_counter(); req=grpc_request(context); status=200; error=None
        try:
            data=MessageToDict(message,preserving_proto_field_name=True)
            with Session.begin() as db:
                gate(db,'grpc'); authorized(req,db,scope='users:write' if write else 'users:read',permission='USER_UPDATE' if write else 'CUSTOMER_READ')
                result=callback(req,db,data)
            return grpc_struct(result)
        except HTTPException as exc:
            status=exc.status_code; error=str(exc.detail)
            code={400:grpc.StatusCode.INVALID_ARGUMENT,401:grpc.StatusCode.UNAUTHENTICATED,403:grpc.StatusCode.PERMISSION_DENIED,404:grpc.StatusCode.NOT_FOUND,409:grpc.StatusCode.ALREADY_EXISTS,503:grpc.StatusCode.UNAVAILABLE}.get(status,grpc.StatusCode.INTERNAL)
            context.abort(code,error)
        finally:
            with Session.begin() as db:
                save(db,'request',dict(id=req.state.correlationId,correlationId=req.state.correlationId,timestamp=now(),method='POST',path='/grpc.IdentityService/'+name,protocol='grpc',status=status,durationMs=round((time.perf_counter()-started)*1000,2),actor=req.state.actor,authentication=req.state.authentication,decision='denied' if status>=400 else 'allowed',error=error,userId=req.state.userId))
    return invoke
def start_grpc_server():
    server=grpc.server(futures.ThreadPoolExecutor(max_workers=8),options=[('grpc.max_receive_message_length',1048576),('grpc.max_send_message_length',1048576)])
    callbacks={
        'ListUsers':grpc_call('ListUsers',False,lambda r,d,x:{'users':[api_user(r,d,u) for u in rows(d,'user') if not u['deleted']]}),
        'GetUser':grpc_call('GetUser',False,lambda r,d,x:{'user':api_user(r,d,required(d,'user',x.get('id','')))}),
        'CreateUser':grpc_call('CreateUser',True,lambda r,d,x:{'user':api_user(r,d,create_user(d,r,x))}),
        'UpdateUser':grpc_call('UpdateUser',True,lambda r,d,x:{'user':api_user(r,d,required(d,'user',update_user(d,r,x.pop('id',''),x)['id']))}),
        'DisableUser':grpc_call('DisableUser',True,lambda r,d,x:{'user':api_user(r,d,required(d,'user',update_user(d,r,x.get('id',''),{'active':False})['id']))}),
    }
    handlers={name:grpc.unary_unary_rpc_method_handler(callback,request_deserializer=Struct.FromString,response_serializer=Struct.SerializeToString) for name,callback in callbacks.items()}
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler('identitylab.v1.IdentityService',handlers),))
    address=os.getenv('GRPC_BIND','0.0.0.0:50051')
    if not server.add_insecure_port(address): raise RuntimeError('Unable to bind gRPC service at '+address)
    server.start(); return server
@asynccontextmanager
async def lifespan(app):
    seed(); grpc_server=start_grpc_server() if os.getenv('GRPC_ENABLED','true').lower()=='true' else None
    try: yield
    finally:
        if grpc_server: grpc_server.stop(grace=2)
app=FastAPI(title='Identity API Lab by Dinesh',version='1.5.0',lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware,allowed_hosts=[x.strip() for x in os.getenv('ALLOWED_HOSTS','localhost,127.0.0.1,testserver,*.onrender.com').split(',') if x.strip()])
def openapi_schema():
    if app.openapi_schema: return app.openapi_schema
    schema=get_openapi(title='Identity API Lab by Dinesh',version='1.5.0',description='Local multi-protocol IAM integration lab designed and built by Dinesh, with seven working client authentication methods.',routes=app.routes)
    schemes=schema.setdefault('components',{}).setdefault('securitySchemes',{})
    schemes.update({'OAuth2ClientCredentials':{'type':'oauth2','flows':{'clientCredentials':{'tokenUrl':'/oauth/token','scopes':{s:s for s in SCOPES}}}},'OAuth2AuthorizationCodePKCE':{'type':'oauth2','flows':{'authorizationCode':{'authorizationUrl':'/oauth/authorize','tokenUrl':'/oauth/token','scopes':{s:s for s in SCOPES}}}},'ApiKeyAuth':{'type':'apiKey','in':'header','name':'X-API-Key'},'HttpBasic':{'type':'http','scheme':'basic'},'JwtBearer':{'type':'http','scheme':'bearer','bearerFormat':'JWT'},'HmacSignature':{'type':'apiKey','in':'header','name':'X-Signature','description':'Also send X-Client-ID, X-Timestamp and X-Nonce.'},'HttpDigest':{'type':'http','scheme':'digest'},'BrowserSession':{'type':'apiKey','in':'cookie','name':'lab_session','description':'Portal session; mutations also require X-CSRF-Token.'}})
    for path,item in schema.get('paths',{}).items():
        for operation in item.values():
            if not isinstance(operation,dict): continue
            if path.startswith(('/api/v1','/scim/','/odata/','/jsonrpc','/graphql','/soap')): operation['security']=[{'OAuth2ClientCredentials':[]},{'OAuth2AuthorizationCodePKCE':[]},{'ApiKeyAuth':[]},{'HttpBasic':[]},{'JwtBearer':[]},{'HmacSignature':[]},{'HttpDigest':[]},{'BrowserSession':[]}]
            elif path.startswith(('/admin-api','/banking','/auth/me','/auth/logout')): operation['security']=[{'BrowserSession':[]}]
    app.openapi_schema=schema; return schema
app.openapi=openapi_schema
RATE_BUCKETS={}
def protocol(path):
    return 'scim11' if path.startswith('/scim/v1') else 'scim' if path.startswith('/scim/v2') else 'odata' if path.startswith('/odata/') else 'jsonrpc' if path=='/jsonrpc' else 'webhooks' if path.startswith('/admin-api/webhook') else 'csvsftp' if path.startswith(('/api/v1/csv','/admin-api/sftp')) else 'rest' if path.startswith('/api/v1') else 'graphql' if path=='/graphql' else 'soap' if path=='/soap' else 'grpc' if path.startswith('/grpc') else 'oauth' if path.startswith('/oauth') else 'portal'
@app.middleware('http')
async def observe(request,call_next):
    start=time.perf_counter(); request.state.correlationId=uid(); request.state.actor='anonymous'; request.state.authentication='none'; request.state.decision='pending'; request.state.userId=None
    try:
        response=None
        if request.method in ('POST','PUT','PATCH'):
            chunks=[]; size=0
            async for chunk in request.stream():
                size+=len(chunk)
                if size>1048576: response=JSONResponse({'detail':'Request exceeds 1 MiB limit'},413); break
                chunks.append(chunk)
            if response is None: request._body=b''.join(chunks)
        if request.url.path in ('/auth/login','/oauth/token'):
            key=((request.client.host if request.client else 'local'),request.url.path); tick=time.monotonic(); hits=[t for t in RATE_BUCKETS.get(key,[]) if tick-t<60]
            limit=int(os.getenv('AUTH_LOGIN_RATE_LIMIT','30')) if request.url.path=='/auth/login' else int(os.getenv('OAUTH_TOKEN_RATE_LIMIT','120'))
            if len(hits)>=limit: response=JSONResponse({'detail':'Rate limit exceeded'},429,headers={'Retry-After':'60'})
            else: hits.append(tick)
            RATE_BUCKETS[key]=hits
            if len(RATE_BUCKETS)>10000:
                for old in list(RATE_BUCKETS):
                    if not RATE_BUCKETS[old] or tick-RATE_BUCKETS[old][-1]>60: RATE_BUCKETS.pop(old,None)
        if response is None: response=await call_next(request)
    except Exception:
        response=JSONResponse({'detail':'Internal request failure','correlationId':request.state.correlationId},500)
    response.headers['X-Correlation-ID']=request.state.correlationId
    response.headers['X-Content-Type-Options']='nosniff'; response.headers['Referrer-Policy']='same-origin'; response.headers['Cache-Control']='no-store'
    response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=(), payment=(), usb=()'
    response.headers['Cross-Origin-Opener-Policy']='same-origin'; response.headers['Cross-Origin-Resource-Policy']='same-origin'
    if os.getenv('COOKIE_SECURE','false').lower()=='true' or request.headers.get('x-forwarded-proto')=='https': response.headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    if request.url.path.startswith(('/api/','/scim/','/odata/','/jsonrpc','/soap','/graphql','/oauth/','/auth/','/banking/','/admin-api/')) and request.url.path not in ['/admin-api/requests','/admin-api/dashboard','/admin-api/audit','/auth/me']:
        with Session.begin() as db:
            save(db,'request',dict(id=request.state.correlationId,correlationId=request.state.correlationId,timestamp=now(),method=request.method,path=request.url.path,protocol=protocol(request.url.path),status=response.status_code,durationMs=round((time.perf_counter()-start)*1000,2),actor=request.state.actor,authentication=request.state.authentication,decision='denied' if response.status_code>=400 else 'allowed',error='Request rejected' if response.status_code>=400 else None,userId=request.state.userId))
            entries=rows(db,'request')
            if len(entries)>3000:
                for x in sorted(entries,key=lambda v:v['timestamp'])[:len(entries)-3000]: db.delete(db.get(Record,'request:'+x['id']))
    return response
def audit(db,req,action,target,changes=None):
    request_id=getattr(req.state,'correlationId',None)
    save(db,'audit',dict(id=uid(),timestamp=now(),actor=req.state.actor,action=action,targetId=target,protocol=protocol(req.url.path),correlationId=request_id,changes=changes or {})); req.state.userId=target
def authorize_client(req,client,granted_scopes,scope,method,method_id):
    if not client or not client['active']: raise HTTPException(401,'Client revoked or invalid')
    if method_id not in client.get('authenticationMethods',['oauth2_client_credentials']): raise HTTPException(401,'Authentication method is not enabled for this client')
    req.state.actor=client['name']; req.state.authentication=method; req.state.apiClient=client
    adapter=protocol(req.url.path); allowed_protocols=client.get('protocols',['rest','scim','soap11','soap12','graphql'])
    if adapter in ('rest','scim','scim11','odata','grpc','jsonrpc','csvsftp') and adapter not in allowed_protocols: raise HTTPException(403,'Client is not permitted to use this protocol')
    if adapter=='soap' and not any(p in allowed_protocols for p in ('soap11','soap12')): raise HTTPException(403,'Client is not permitted to use SOAP')
    if scope and scope not in granted_scopes: raise HTTPException(403,'Insufficient scope')
    return {'id':client['id'],'permissions':[],'isClient':True}
def authorized(req,db,scope=None,permission=None,admin=False):
    header=req.headers.get('authorization',''); api_key=req.headers.get('x-api-key')
    if header.lower().startswith('bearer '):
        value=header[7:]
        if value.count('.')==2:
            claims=verify_jwt(value); client=get(db,'client',claims.get('sub')) if claims else None
            if not claims or not client or claims.get('ver')!=client.get('credentialVersion',1): raise HTTPException(401,'Invalid or expired JWT',headers={'WWW-Authenticate':'Bearer'})
            if admin: raise HTTPException(403,'Administrative browser session required')
            return authorize_client(req,client,claims.get('scope','').split(),scope,'JWT Bearer','jwt_bearer')
        tok=next((t for t in rows(db,'token') if secrets.compare_digest(t['hash'],digest(value))),None)
        if not tok or tok['revoked'] or tok['expiresAt']<time.time(): raise HTTPException(401,'Invalid or expired access token',headers={'WWW-Authenticate':'Bearer'})
        if admin: raise HTTPException(403,'Administrative browser session required')
        method_id='oauth2_authorization_code_pkce' if tok.get('grantType')=='authorization_code' else 'oauth2_client_credentials'
        return authorize_client(req,get(db,'client',tok['clientId']),tok['scopes'],scope,'OAuth 2.0 Bearer',method_id)
    if api_key is not None:
        client=next((c for c in rows(db,'client') if c.get('apiKeyHash') and secrets.compare_digest(c['apiKeyHash'],digest(api_key))),None)
        if not client: raise HTTPException(401,'Invalid API key',headers={'WWW-Authenticate':'ApiKey'})
        if admin: raise HTTPException(403,'Administrative browser session required')
        return authorize_client(req,client,client['scopes'],scope,'API Key','api_key')
    if req.headers.get('x-signature') is not None:
        client=get(db,'client',req.headers.get('x-client-id','')); timestamp=req.headers.get('x-timestamp',''); nonce=req.headers.get('x-nonce',''); signature=req.headers.get('x-signature','')
        try: fresh=abs(time.time()-int(timestamp))<300
        except ValueError: fresh=False
        if not client or not fresh or not nonce or nonce in NONCES: raise HTTPException(401,'Invalid or replayed HMAC request')
        body=getattr(req,'_body',b'') or b''; canonical='\n'.join([req.method.upper(),req.url.path,timestamp,nonce,hashlib.sha256(body).hexdigest()]); expected=hmac.new(derived_secret(client,'hmac').encode(),canonical.encode(),hashlib.sha256).hexdigest()
        if not secrets.compare_digest(signature,expected): raise HTTPException(401,'Invalid HMAC signature')
        NONCES[nonce]=time.time()
        for old,seen in list(NONCES.items()):
            if time.time()-seen>300: NONCES.pop(old,None)
        if admin: raise HTTPException(403,'Administrative browser session required')
        return authorize_client(req,client,client['scopes'],scope,'HMAC SHA-256','hmac_sha256')
    if header.lower().startswith('digest '):
        values={m.group(1):m.group(2) or m.group(3) for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([^,\s]+))',header[7:])}; client=get(db,'client',values.get('username',''))
        if not client or not valid_digest_nonce(values.get('nonce','')) or values.get('uri')!=req.url.path or values.get('qop')!='auth': raise HTTPException(401,'Invalid Digest authentication',headers={'WWW-Authenticate':f'Digest realm="{REALM}", nonce="{digest_nonce()}", algorithm=MD5, qop="auth"'})
        ha1=hashlib.md5(f'{client["id"]}:{REALM}:{derived_secret(client,"digest")}'.encode()).hexdigest(); ha2=hashlib.md5(f'{req.method}:{values["uri"]}'.encode()).hexdigest(); expected=hashlib.md5(f'{ha1}:{values["nonce"]}:{values.get("nc","")}:{values.get("cnonce","")}:{values["qop"]}:{ha2}'.encode()).hexdigest()
        if not secrets.compare_digest(values.get('response',''),expected): raise HTTPException(401,'Invalid Digest authentication',headers={'WWW-Authenticate':f'Digest realm="{REALM}", nonce="{digest_nonce()}", algorithm=MD5, qop="auth"'})
        if admin: raise HTTPException(403,'Administrative browser session required')
        return authorize_client(req,client,client['scopes'],scope,'HTTP Digest','http_digest')
    if header.lower().startswith('basic '):
        try: client_id,client_secret=base64.b64decode(header[6:],validate=True).decode().split(':',1)
        except Exception: raise HTTPException(401,'Invalid HTTP Basic credentials',headers={'WWW-Authenticate':'Basic realm="Identity API Lab"'})
        client=get(db,'client',client_id); valid=False
        if client:
            try: valid=ph.verify(client['secretHash'],client_secret)
            except (VerifyMismatchError,InvalidHashError,TypeError): pass
        if not valid: raise HTTPException(401,'Invalid HTTP Basic credentials',headers={'WWW-Authenticate':'Basic realm="Identity API Lab"'})
        if admin: raise HTTPException(403,'Administrative browser session required')
        return authorize_client(req,client,client['scopes'],scope,'HTTP Basic','http_basic')
    if header: raise HTTPException(401,'Unsupported Authorization scheme')
    cookie=req.cookies.get('lab_session'); sess=get(db,'session',digest(cookie)) if cookie else None
    if not sess or sess['revoked'] or sess['expiresAt']<time.time(): raise HTTPException(401,'Sign in required',headers={'WWW-Authenticate':f'Digest realm="{REALM}", nonce="{digest_nonce()}", algorithm=MD5, qop="auth"'} if protocol(req.url.path) in ('rest','scim','soap','graphql') else None)
    u=get(db,'user',sess['userId'])
    if not u or not u['active'] or u['locked'] or u['deleted']: raise HTTPException(401,'Account is unavailable')
    req.state.actor=u['username']; req.state.authentication='Session cookie'; req.state.userId=u['id']
    if req.method not in ('GET','HEAD','OPTIONS') and not secrets.compare_digest(req.headers.get('x-csrf-token',''),sess['csrfToken']): raise HTTPException(403,'CSRF token required')
    perms=effective(db,u)
    if admin and not set(perms).intersection(CATALOG[5:]): raise HTTPException(403,'Administrative access required')
    if permission and permission not in perms: raise HTTPException(403,'Permission required: '+permission)
    return public_user(db,u)
def gate(db,p):
    if not required(db,'protocol',p)['enabled']: raise HTTPException(503,p+' protocol is disabled')
def revoke_sessions(db,user_id):
    for s in rows(db,'session'):
        if s['userId']==user_id: s['revoked']=True; save(db,'session',s)
def validate_roles(db,ids):
    if not isinstance(ids,list) or any(not get(db,'role',x) for x in ids): raise HTTPException(400,'Unknown role')
def permission_ids(db): return set(CATALOG)|{p['id'] for p in rows(db,'permission')}
def validate_permissions(db,ids):
    if not isinstance(ids,list) or len(ids)!=len(set(ids)) or any(x not in permission_ids(db) for x in ids): raise HTTPException(400,'Unknown or duplicate permission')
def set_groups(db,user_id,ids):
    if not isinstance(ids,list) or any(not get(db,'group',x) for x in ids): raise HTTPException(400,'Unknown group')
    wanted=set(ids)
    for group in rows(db,'group'):
        members=set(group.get('members',[]))
        if group['id'] in wanted: members.add(user_id)
        else: members.discard(user_id)
        group['members']=sorted(members); save(db,'group',group)
def create_user(db,req,data):
    enforce_write_attributes(req,data)
    if data.get('roles'): authorized(req,db,scope='roles:write',permission='ACCESS_MANAGE')
    if data.get('groups'): authorized(req,db,scope='groups:write',permission='ACCESS_MANAGE')
    username=str(data.get('username','')).strip()
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{2,100}',username): raise HTTPException(400,'A valid username is required')
    if any(u['username'].lower()==username.lower() for u in rows(db,'user')): raise HTTPException(409,'Username already exists')
    password=data.get('password') or secrets.token_urlsafe(24)
    if len(password)<10: raise HTTPException(400,'Password must have at least 10 characters')
    validate_roles(db,data.get('roles',[])); id=uid()
    u=dict(id=id,username=username,displayName=data.get('displayName',username),firstName=data.get('firstName',''),lastName=data.get('lastName',''),email=data.get('email',''),department=data.get('department',''),jobTitle=data.get('jobTitle',''),country=data.get('country',''),city=data.get('city',''),active=data.get('active',True),locked=False,deleted=False,passwordResetRequired=False,roles=data.get('roles',[]),passwordHash=ph.hash(password),failedLogins=0,createdAt=now(),updatedAt=now())
    if not isinstance(u['active'],bool): raise HTTPException(400,'active must be boolean')
    # A deterministic primary-key reservation enforces case-insensitive uniqueness across transactions.
    db.add(Record(key='username:'+digest(username.lower()),kind='username',body=json.dumps({'id':digest(username.lower()),'userId':id}))); db.flush()
    save(db,'user',u)
    if 'groups' in data: set_groups(db,id,data['groups'])
    audit(db,req,'user.create',id,{'username':username}); emit_webhooks(db,'user.created',public_user(db,u)); return public_user(db,u)
def update_user(db,req,id,data):
    enforce_write_attributes(req,data)
    u=required(db,'user',id)
    if 'roles' in data: authorized(req,db,scope='roles:write',permission='ACCESS_MANAGE')
    if 'groups' in data: authorized(req,db,scope='groups:write',permission='ACCESS_MANAGE')
    if any(k in data for k in ('active','locked','deleted')): authorized(req,db,scope='users:write',permission='USER_STATUS_MANAGE')
    allowed={'displayName','firstName','lastName','email','department','jobTitle','country','city','active','locked','deleted','roles','passwordResetRequired'}
    if 'roles' in data: validate_roles(db,data['roles'])
    for field in ['active','locked','deleted','passwordResetRequired']:
        if field in data and not isinstance(data[field],bool): raise HTTPException(400,field+' must be boolean')
    changes={k:{'before':u.get(k),'after':v} for k,v in data.items() if k in allowed and u.get(k)!=v}
    u.update({k:v for k,v in data.items() if k in allowed}); u['updatedAt']=now(); save(db,'user',u)
    if 'groups' in data:
        before=[g['id'] for g in rows(db,'group') if id in g.get('members',[])]
        set_groups(db,id,data['groups']); changes['groups']={'before':before,'after':data['groups']}
    if not u['active'] or u['locked'] or u['deleted']: revoke_sessions(db,id)
    event='user.deleted' if changes.get('deleted',{}).get('after') is True else 'user.disabled' if changes.get('active',{}).get('after') is False else 'user.updated'
    audit(db,req,'user.update',id,changes); emit_webhooks(db,event,public_user(db,u)); return public_user(db,u)

@app.get('/health')
def health():
    with Session() as db: db.execute(select(Record.key).limit(1))
    return {'status':'ok','version':'1.5.0','database':engine.dialect.name,'author':'Dinesh','authorUrl':'https://www.linkedin.com/in/dineshwarmanukonda/'}
@app.post('/auth/login')
async def login(req:Request):
    try: data=await req.json()
    except (ValueError,UnicodeDecodeError): raise HTTPException(400,'Valid JSON body required')
    if not isinstance(data,dict) or not isinstance(data.get('password',''),str): raise HTTPException(400,'Invalid login body')
    with Session.begin() as db:
        u=next((u for u in rows(db,'user') if u['username'].lower()==str(data.get('username','')).lower()),None)
        valid=False
        if u:
            try: valid=ph.verify(u['passwordHash'],data.get('password',''))
            except (VerifyMismatchError,InvalidHashError,TypeError): pass
        if not valid or not u or not u['active'] or u['locked'] or u['deleted']:
            if u and not valid:
                u['failedLogins']=u.get('failedLogins',0)+1
                if u['failedLogins']>=10: u['locked']=True; revoke_sessions(db,u['id'])
                save(db,'user',u)
            return JSONResponse({'detail':'Invalid credentials or unavailable account'},401)
        u['failedLogins']=0; save(db,'user',u); secret=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
        sess=dict(id=digest(secret),userId=u['id'],username=u['username'],csrfToken=csrf,createdAt=now(),expiresAt=time.time()+28800,revoked=False)
        save(db,'session',sess); req.state.actor=u['username']; audit(db,req,'session.login',u['id'])
        response=JSONResponse({'user':public_user(db,u),'csrfToken':csrf}); response.set_cookie('lab_session',secret,httponly=True,samesite='strict',secure=os.getenv('COOKIE_SECURE','false')=='true',max_age=28800,path='/'); return response
@app.get('/auth/me')
def me(req:Request):
    with Session() as db:
        u=authorized(req,db); s=get(db,'session',digest(req.cookies.get('lab_session','')))
        impersonator=get(db,'user',s.get('impersonatorUserId')) if s.get('impersonatorUserId') else None
        return {'user':u,'csrfToken':s['csrfToken'],'impersonation':({'active':True,'administrator':public_user(db,impersonator)} if impersonator else None)}
@app.post('/auth/logout')
def logout(req:Request):
    with Session.begin() as db:
        authorized(req,db); s=required(db,'session',digest(req.cookies.get('lab_session',''))); s['revoked']=True; save(db,'session',s)
    r=JSONResponse({'ok':True}); r.delete_cookie('lab_session'); return r

def public_sso_provider(provider):
    return {k:v for k,v in provider.items() if k not in ('clientSecretEncrypted','signingCertificate')}
SSO_MAPPING_FIELDS=('username','email','displayName','firstName','lastName','department','jobTitle','country','city')
def mapped_claim(claims,path):
    value=claims
    for part in str(path or '').split('.'):
        if not part or not isinstance(value,dict): return ''
        value=value.get(part,'')
    return value if not isinstance(value,(dict,list)) else ''
def sso_configuration(data,existing=None):
    kind=str(data.get('type',existing.get('type') if existing else 'oidc')).lower(); preset=str(data.get('preset',existing.get('preset') if existing else 'generic'))
    if kind not in ('oidc','saml'): raise HTTPException(400,'SSO type must be oidc or saml')
    provider={**(existing or {}),**{k:v for k,v in data.items() if k not in ('clientSecret','signingCertificate')}}; provider['type']=kind; provider['preset']=preset; provider['name']=str(provider.get('name','')).strip()[:100]
    if not provider['name']: raise HTTPException(400,'Provider name is required')
    if kind=='oidc':
        if preset=='entra':
            tenant=re.sub(r'[^A-Za-z0-9._-]','',str(data.get('tenantId',provider.get('tenantId','common')))); provider.update(tenantId=tenant,issuer=f'https://login.microsoftonline.com/{tenant}/v2.0',authorizationEndpoint=f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize',tokenEndpoint=f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',jwksUri=f'https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys')
        else:
            provider['issuer']=safe_sso_url(provider.get('issuer'))
            if preset=='okta': provider.update(authorizationEndpoint=provider['issuer']+'/v1/authorize',tokenEndpoint=provider['issuer']+'/v1/token',jwksUri=provider['issuer']+'/v1/keys')
            else:
                for field in ('authorizationEndpoint','tokenEndpoint','jwksUri'):
                    if provider.get(field): provider[field]=safe_sso_url(provider[field])
        if not provider.get('clientId'): raise HTTPException(400,'OIDC client ID is required')
        if data.get('clientSecret'): provider['clientSecretEncrypted']=encrypt_secret(str(data['clientSecret']))
        if not provider.get('clientSecretEncrypted'): raise HTTPException(400,'OIDC client secret is required')
        provider['scopes']=data.get('scopes',provider.get('scopes',['openid','profile','email']))
        if 'openid' not in provider['scopes']: raise HTTPException(400,'OIDC scopes must include openid')
    else:
        provider['entityId']=str(provider.get('entityId','')).strip(); provider['ssoUrl']=safe_sso_url(provider.get('ssoUrl')); certificate=str(data.get('signingCertificate','')).strip()
        if certificate: provider['signingCertificate']=certificate
        if not provider['entityId'] or not provider.get('signingCertificate'): raise HTTPException(400,'SAML entity ID and signing certificate are required')
    provider['enabled']=bool(data.get('enabled',provider.get('enabled',True))); provider['jitProvisioning']=bool(data.get('jitProvisioning',provider.get('jitProvisioning',True))); provider['defaultRoles']=data.get('defaultRoles',provider.get('defaultRoles',['viewer'])); provider['allowedDomains']=[x.lower() for x in data.get('allowedDomains',provider.get('allowedDomains',[])) if x]
    defaults={'username':'preferred_username','email':'email','displayName':'name','firstName':'given_name','lastName':'family_name','department':'department','jobTitle':'job_title','country':'country','city':'city'}
    mapping=data.get('claimMapping',provider.get('claimMapping',defaults))
    if not isinstance(mapping,dict) or any(k not in SSO_MAPPING_FIELDS or not isinstance(v,str) or len(v)>120 for k,v in mapping.items()): raise HTTPException(400,'SSO claim mapping contains an invalid identity field or claim path')
    provider['claimMapping']={**defaults,**mapping}; provider['correlationAttribute']=data.get('correlationAttribute',provider.get('correlationAttribute','email'))
    if provider['correlationAttribute'] not in ('email','username'): raise HTTPException(400,'Correlation attribute must be email or username')
    return provider
@app.get('/sso/providers')
def sso_public():
    with Session() as db: return [{k:v for k,v in public_sso_provider(p).items() if k in ('id','name','type','preset','enabled')} for p in rows(db,'sso_provider') if p.get('enabled') and p.get('type')=='oidc']
@app.get('/admin-api/sso-providers')
def sso_admin_list(req:Request):
    with Session() as db: authorized(req,db,admin=True,permission='SYSTEM_CONFIGURE'); return [public_sso_provider(p) for p in rows(db,'sso_provider')]
@app.post('/admin-api/sso-providers',status_code=201)
async def sso_admin_create(req:Request):
    data=await req.json()
    with Session.begin() as db:
        authorized(req,db,admin=True,permission='SYSTEM_CONFIGURE'); provider=sso_configuration(data); provider.update(id=uid(),createdAt=now()); validate_roles(db,provider['defaultRoles']); save(db,'sso_provider',provider); audit(db,req,'sso_provider.create',provider['id'],{'type':provider['type'],'preset':provider['preset']}); return public_sso_provider(provider)
@app.patch('/admin-api/sso-providers/{id}')
async def sso_admin_update(id:str,req:Request):
    data=await req.json()
    with Session.begin() as db:
        authorized(req,db,admin=True,permission='SYSTEM_CONFIGURE'); provider=sso_configuration(data,required(db,'sso_provider',id)); validate_roles(db,provider['defaultRoles']); provider['updatedAt']=now(); save(db,'sso_provider',provider); audit(db,req,'sso_provider.update',id,{'fields':sorted(k for k in data if k not in ('clientSecret','signingCertificate'))}); return public_sso_provider(provider)
@app.delete('/admin-api/sso-providers/{id}',status_code=204)
def sso_admin_delete(id:str,req:Request):
    with Session.begin() as db: authorized(req,db,admin=True,permission='SYSTEM_CONFIGURE'); required(db,'sso_provider',id); db.delete(db.get(Record,'sso_provider:'+id)); audit(db,req,'sso_provider.delete',id); return Response(status_code=204)
@app.get('/sso/{id}/metadata')
def saml_metadata(id:str,req:Request):
    with Session() as db:
        provider=required(db,'sso_provider',id)
        if provider['type']!='saml': raise HTTPException(404,'SAML provider not found')
        base=os.getenv('PUBLIC_URL',str(req.base_url).rstrip('/')); entity=base+'/sso/'+id+'/metadata'; acs=base+'/sso/'+id+'/acs'
        return Response(f'<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}"><SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0" isDefault="true"/></SPSSODescriptor></EntityDescriptor>',media_type='application/samlmetadata+xml')
@app.post('/sso/{id}/acs')
def saml_acs(id:str): raise HTTPException(501,'SAML assertion validation requires the deployment SAML verification adapter; use the generated SP metadata to complete that integration')
@app.get('/sso/{id}/login')
def sso_login(id:str,req:Request):
    with Session.begin() as db:
        provider=required(db,'sso_provider',id)
        if not provider.get('enabled'): raise HTTPException(404,'SSO provider is disabled')
        if provider['type']!='oidc': raise HTTPException(501,'This provider is configured for SAML metadata exchange and needs the deployment SAML verification adapter')
        if not all(provider.get(x) for x in ('authorizationEndpoint','tokenEndpoint','jwksUri')):
            discovery=remote_json(provider['issuer']+'/.well-known/openid-configuration'); provider.update(authorizationEndpoint=discovery['authorization_endpoint'],tokenEndpoint=discovery['token_endpoint'],jwksUri=discovery['jwks_uri']); save(db,'sso_provider',provider)
        state=secrets.token_urlsafe(32); verifier=secrets.token_urlsafe(64); nonce=secrets.token_urlsafe(32); challenge=b64url(hashlib.sha256(verifier.encode()).digest()); redirect_uri=os.getenv('PUBLIC_URL',str(req.base_url).rstrip('/'))+'/sso/'+id+'/callback'
        save(db,'sso_state',dict(id=digest(state),providerId=id,verifier=verifier,nonce=nonce,redirectUri=redirect_uri,expiresAt=time.time()+300,used=False)); params={'response_type':'code','client_id':provider['clientId'],'redirect_uri':redirect_uri,'scope':' '.join(provider['scopes']),'state':state,'nonce':nonce,'code_challenge':challenge,'code_challenge_method':'S256'}; return RedirectResponse(provider['authorizationEndpoint']+'?'+urlencode(params))
@app.get('/sso/{id}/callback')
def sso_callback(id:str,req:Request):
    state_value=req.query_params.get('state',''); code=req.query_params.get('code','')
    with Session.begin() as db:
        provider=required(db,'sso_provider',id); state=get(db,'sso_state',digest(state_value))
        if not code or not state or state['used'] or state['expiresAt']<time.time() or state['providerId']!=id: raise HTTPException(400,'Invalid or expired SSO response')
        token=remote_json(provider['tokenEndpoint'],{'grant_type':'authorization_code','client_id':provider['clientId'],'client_secret':decrypt_secret(provider['clientSecretEncrypted']),'code':code,'redirect_uri':state['redirectUri'],'code_verifier':state['verifier']},{'Content-Type':'application/x-www-form-urlencoded'}); claims=validate_id_token(token.get('id_token',''),provider,state['nonce']); state['used']=True; save(db,'sso_state',state)
        mapping=provider['claimMapping']; value=lambda field:mapped_claim(claims,mapping.get(field,field)); email=str(value('email') or value('username')).lower(); username=re.sub(r'[^A-Za-z0-9_.@-]','.',str(value('username') or email or claims.get('sub'))).strip('.')[:100]
        if not username: raise HTTPException(400,'The identity provider did not return a usable username')
        if provider.get('allowedDomains') and (not email or email.split('@')[-1] not in provider['allowedDomains']): raise HTTPException(403,'Email domain is not allowed for this provider')
        correlation=provider.get('correlationAttribute','email'); user=next((u for u in rows(db,'user') if (correlation=='email' and email and u.get('email','').lower()==email) or (correlation=='username' and u['username'].lower()==username.lower())),None)
        if not user:
            if not provider.get('jitProvisioning'): raise HTTPException(403,'No linked employee account exists')
            validate_roles(db,provider['defaultRoles']); user=dict(id=uid(),username=username,firstName=str(value('firstName')),lastName=str(value('lastName')),displayName=str(value('displayName') or username),email=email,department=str(value('department')),jobTitle=str(value('jobTitle')),country=str(value('country')),city=str(value('city')),active=True,locked=False,deleted=False,passwordResetRequired=False,roles=provider['defaultRoles'],passwordHash=ph.hash(secrets.token_urlsafe(40)),failedLogins=0,createdAt=now(),updatedAt=now(),identityProviderId=id); db.add(Record(key='username:'+digest(username.lower()),kind='username',body=json.dumps({'id':digest(username.lower()),'userId':user['id']}))); save(db,'user',user)
        if not user['active'] or user['locked'] or user['deleted']: raise HTTPException(403,'Linked employee account is unavailable')
        secret=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32); save(db,'session',dict(id=digest(secret),userId=user['id'],username=user['username'],csrfToken=csrf,createdAt=now(),expiresAt=time.time()+28800,revoked=False,identityProviderId=id)); req.state.actor=user['username']; req.state.authentication='OIDC SSO: '+provider['name']; audit(db,req,'session.sso_login',user['id'],{'providerId':id}); response=RedirectResponse('/bank'); response.set_cookie('lab_session',secret,httponly=True,samesite='lax',secure=os.getenv('COOKIE_SECURE','false')=='true',max_age=28800,path='/'); return response

@app.post('/admin-api/impersonate/{user_id}')
def impersonate(user_id:str,req:Request):
    """Let an authorized administrator preview the exact portal access of an active user."""
    with Session.begin() as db:
        administrator=authorized(req,db,admin=True,permission='USER_UPDATE')
        target=required(db,'user',user_id)
        if not target['active'] or target['locked'] or target['deleted']: raise HTTPException(409,'Only an active, unlocked identity can be previewed')
        if target['id']==administrator['id']: raise HTTPException(409,'You are already using this identity')
        session=required(db,'session',digest(req.cookies.get('lab_session','')))
        if session.get('impersonatorUserId'): raise HTTPException(409,'Stop the current user preview before starting another')
        session.update(userId=target['id'],username=target['username'],impersonatorUserId=administrator['id'],impersonatorUsername=administrator['username'])
        save(db,'session',session); audit(db,req,'session.impersonate',target['id'],{'administratorId':administrator['id']})
        return {'user':public_user(db,target),'csrfToken':session['csrfToken'],'impersonation':{'active':True,'administrator':administrator}}

@app.post('/auth/impersonation/stop')
def stop_impersonation(req:Request):
    with Session.begin() as db:
        cookie=req.cookies.get('lab_session'); session=get(db,'session',digest(cookie)) if cookie else None
        if not session or session['revoked'] or session['expiresAt']<time.time(): raise HTTPException(401,'Sign in required')
        if not secrets.compare_digest(req.headers.get('x-csrf-token',''),session['csrfToken']): raise HTTPException(403,'CSRF token required')
        administrator=get(db,'user',session.get('impersonatorUserId')) if session.get('impersonatorUserId') else None
        if not administrator or not administrator['active'] or administrator['locked'] or administrator['deleted']: raise HTTPException(409,'The administrator session can no longer be restored')
        previewed_id=session['userId']; session.update(userId=administrator['id'],username=administrator['username']); session.pop('impersonatorUserId',None); session.pop('impersonatorUsername',None); save(db,'session',session)
        req.state.actor=administrator['username']; req.state.authentication='Impersonation restore'; audit(db,req,'session.impersonate.stop',previewed_id,{'administratorId':administrator['id']})
        return {'user':public_user(db,administrator),'csrfToken':session['csrfToken'],'impersonation':None}

@app.get('/admin-api/dashboard')
def dashboard(req:Request):
    with Session() as db:
        authorized(req,db,admin=True,permission='API_MANAGE'); users=rows(db,'user'); logs=rows(db,'request')
        clients=rows(db,'client'); sessions=rows(db,'session'); tokens=rows(db,'token'); current=datetime.now(timezone.utc)
        parse=lambda value:datetime.fromisoformat(str(value).replace('Z','+00:00'))
        timeline=[]
        for offset in range(11,-1,-1):
            start=current.replace(minute=0,second=0,microsecond=0)-timedelta(hours=offset); end=start+timedelta(hours=1); bucket=[x for x in logs if start<=parse(x['timestamp'])<end]
            timeline.append({'label':start.strftime('%H:%M'),'requests':len(bucket),'errors':sum(x['status']>=400 for x in bucket),'latency':round(sum(x['durationMs'] for x in bucket)/max(len(bucket),1),1),'byProtocol':{key:sum(x['protocol']==key for x in bucket) for key in ('rest','scim','soap','graphql','oauth','portal')}})
        protocols=[]
        for key in sorted({x['protocol'] for x in logs}|{'rest','scim','soap','graphql','oauth','portal'}):
            subset=[x for x in logs if x['protocol']==key]; protocols.append({'id':key,'value':len(subset),'errors':sum(x['status']>=400 for x in subset),'latency':round(sum(x['durationMs'] for x in subset)/max(len(subset),1),1)})
        auth=[]
        for key in sorted({x.get('authentication','none') for x in logs}): auth.append({'id':key,'value':sum(x.get('authentication','none')==key for x in logs)})
        calendar=[]
        for offset in range(20,-1,-1):
            day=(current-timedelta(days=offset)).date(); calendar.append({'date':day.isoformat(),'value':sum(parse(x['timestamp']).date()==day for x in logs)})
        countries=[{'id':country,'value':sum(u.get('country')==country for u in users)} for country in sorted({u.get('country') for u in users if u.get('country')})]
        departments=[{'id':department,'value':sum(u.get('department')==department for u in users)} for department in sorted({u.get('department') for u in users if u.get('department')})]
        return dict(users=len(users),activeUsers=sum(u['active'] and not u['deleted'] for u in users),clients=len(clients),requests=len(logs),errorRate=round(100*sum(x['status']>=400 for x in logs)/max(len(logs),1),1),avgDurationMs=round(sum(x['durationMs'] for x in logs)/max(len(logs),1),1),protocols=rows(db,'protocol'),recentRequests=sorted(logs,key=lambda x:x['timestamp'],reverse=True)[:12],recentAudit=sorted(rows(db,'audit'),key=lambda x:x['timestamp'],reverse=True)[:10],charts={'timeline':timeline,'protocols':protocols,'authentication':auth,'calendar':calendar,'countries':countries,'departments':departments,'userHealth':[{'id':'Active','value':sum(u['active'] and not u['locked'] and not u['deleted'] for u in users)},{'id':'Disabled','value':sum(not u['active'] and not u['deleted'] for u in users)},{'id':'Locked','value':sum(u['locked'] and not u['deleted'] for u in users)},{'id':'Deleted','value':sum(u['deleted'] for u in users)}],'sessions':[{'id':'Active','value':sum(not s['revoked'] and s['expiresAt']>time.time() for s in sessions)},{'id':'Revoked','value':sum(s['revoked'] for s in sessions)},{'id':'Expired','value':sum(not s['revoked'] and s['expiresAt']<=time.time() for s in sessions)}],'risk':[{'id':'Denied requests','value':sum(x['status']>=400 for x in logs)},{'id':'Locked identities','value':sum(u['locked'] for u in users)},{'id':'Failed logins','value':sum(u.get('failedLogins',0) for u in users)},{'id':'Revoked clients','value':sum(not c['active'] for c in clients)},{'id':'Revoked tokens','value':sum(t['revoked'] for t in tokens)}]})
@app.get('/admin-api/{collection}')
def admin_list(collection:str,req:Request):
    kinds={'users':'user','roles':'role','groups':'group','clients':'client','protocols':'protocol','requests':'request','audit':'audit','sessions':'session','tokens':'token'}
    with Session() as db:
        needed={'users':'USER_UPDATE','roles':'ACCESS_MANAGE','groups':'ACCESS_MANAGE','clients':'CLIENT_MANAGE','protocols':'API_MANAGE','requests':'AUDIT_READ','audit':'AUDIT_READ','sessions':'SESSION_REVOKE','tokens':'CLIENT_MANAGE','settings':'SYSTEM_CONFIGURE','permissions':'ACCESS_MANAGE'}
        authorized(req,db,admin=True,permission=needed.get(collection,'SYSTEM_CONFIGURE'))
        if collection=='permissions': return [{'id':p,'name':p.replace('_',' ').title(),'description':'Built-in server permission','system':True} for p in CATALOG]+rows(db,'permission')
        if collection=='settings': return {'database':engine.dialect.name,'environment':'Local synthetic lab','version':'1.5.0','author':'Dinesh','authorUrl':'https://www.linkedin.com/in/dineshwarmanukonda/','supportedAuthentication':['Session + CSRF','OAuth 2.0 Client Credentials','OAuth 2.0 Authorization Code + PKCE','API Key','HTTP Basic','HTTP Digest','JWT Bearer','HMAC SHA-256','Upstream OpenID Connect + PKCE'],'planned':['SAML assertion verification adapter','mTLS termination'],'tokenLifetimeSeconds':3600,'revokeTokensOnSecretRotation':True}
        if collection not in kinds: raise HTTPException(404,'Unknown resource')
        out=rows(db,kinds[collection])
        if collection=='users': return [public_user(db,u) for u in out]
        if collection=='roles': return [{**role,'system':role['id'] in {x[0] for x in ROLE_DEFS}} for role in out]
        out=[{k:v for k,v in x.items() if k not in ('secretHash','apiKeyHash','hash','csrfToken')} for x in out]
        if collection in ('requests','audit'): out=sorted(out,key=lambda x:x['timestamp'],reverse=True)[:500]
        return out
@app.get('/admin-api/requests/{id}')
def request_detail(id:str,req:Request):
    with Session() as db:
        authorized(req,db,admin=True,permission='AUDIT_READ'); x=required(db,'request',id); return {**x,'audit':[a for a in rows(db,'audit') if a['correlationId']==id]}
@app.patch('/admin-api/protocols/{id}')
async def toggle(id:str,req:Request):
    data=await req.json()
    with Session.begin() as db:
        authorized(req,db,admin=True,permission='API_MANAGE'); p=required(db,'protocol',id)
        if not isinstance(data.get('enabled'),bool): raise HTTPException(400,'enabled must be boolean')
        p['enabled']=data['enabled']; save(db,'protocol',p); audit(db,req,'protocol.configure',id,{'enabled':p['enabled']}); return p
@app.post('/admin-api/clients',status_code=201)
async def client_create(req:Request):
    data=await req.json()
    with Session.begin() as db:
        authorized(req,db,permission='CLIENT_MANAGE',admin=True); scopes=data.get('scopes',SCOPES)
        if not isinstance(scopes,list) or any(s not in SCOPES for s in scopes): raise HTTPException(400,'Unknown scope')
        protocols=data.get('protocols',[p[0] for p in PROTOCOLS])
        if not isinstance(protocols,list) or any(p not in [x[0] for x in PROTOCOLS] for p in protocols): raise HTTPException(400,'Unknown protocol')
        methods=data.get('authenticationMethods',['oauth2_client_credentials'])
        if not isinstance(methods,list) or not methods or any(m not in AUTH_METHODS for m in methods): raise HTTPException(400,'Unknown authentication method')
        redirects=data.get('redirectUris',['http://localhost:8787/oauth/callback'])
        if not isinstance(redirects,list) or any(not re.match(r'^https?://',str(x)) for x in redirects): raise HTTPException(400,'Valid absolute redirect URIs required')
        readable,writable=attribute_policy(data)
        secret=secrets.token_urlsafe(40); api_key='ial_'+secrets.token_urlsafe(40) if 'api_key' in methods else None; id=uid(); c=dict(id=id,clientId=id,name=str(data.get('name','Integration Client'))[:100],scopes=scopes,protocols=protocols,authenticationMethods=methods,redirectUris=redirects,readAttributes=readable,writeAttributes=writable,credentialVersion=1,active=True,createdAt=now(),secretHash=ph.hash(secret),apiKeyHash=digest(api_key) if api_key else None)
        save(db,'client',c); audit(db,req,'client.create',id,{'authenticationMethods':methods,'readAttributes':readable,'writeAttributes':writable}); public={k:v for k,v in c.items() if k not in ('secretHash','apiKeyHash')}; return {**public,'clientSecret':secret,**({'apiKey':api_key} if api_key else {}),**({'hmacSecret':derived_secret(c,'hmac')} if 'hmac_sha256' in methods else {}),**({'digestPassword':derived_secret(c,'digest')} if 'http_digest' in methods else {})}
@app.patch('/admin-api/clients/{id}')
async def client_attribute_policy(id:str,req:Request):
    data=await req.json()
    with Session.begin() as db:
        authorized(req,db,permission='CLIENT_MANAGE',admin=True); client=required(db,'client',id); readable,writable=attribute_policy(data)
        before={'readAttributes':client.get('readAttributes',READABLE_USER_ATTRIBUTES),'writeAttributes':client.get('writeAttributes',WRITABLE_USER_ATTRIBUTES)}
        client['readAttributes']=readable; client['writeAttributes']=writable; save(db,'client',client); audit(db,req,'client.attribute_policy.update',id,{'before':before,'after':{'readAttributes':readable,'writeAttributes':writable}})
        return {k:v for k,v in client.items() if k not in ('secretHash','apiKeyHash')}
@app.post('/admin-api/clients/{id}/{action}')
def client_action(id:str,action:str,req:Request):
    with Session.begin() as db:
        authorized(req,db,permission='CLIENT_MANAGE',admin=True); c=required(db,'client',id)
        if action not in ('rotate','revoke'): raise HTTPException(404,'Unknown operation')
        secret=secrets.token_urlsafe(40); api_key='ial_'+secrets.token_urlsafe(40) if 'api_key' in c.get('authenticationMethods',[]) else None
        if action=='rotate': c['credentialVersion']=c.get('credentialVersion',1)+1; c['secretHash']=ph.hash(secret); c['apiKeyHash']=digest(api_key) if api_key else None
        else: c['active']=False
        save(db,'client',c)
        for t in rows(db,'token'):
            if t['clientId']==id: t['revoked']=True; save(db,'token',t)
        audit(db,req,'client.'+action,id)
        if action=='revoke': emit_webhooks(db,'client.revoked',{'id':id,'name':c['name']})
        return {'id':id,'clientId':c['clientId'],'clientSecret':secret,**({'apiKey':api_key} if api_key else {}),**({'hmacSecret':derived_secret(c,'hmac')} if 'hmac_sha256' in c.get('authenticationMethods',[]) else {}),**({'digestPassword':derived_secret(c,'digest')} if 'http_digest' in c.get('authenticationMethods',[]) else {})} if action=='rotate' else {'ok':True}
@app.post('/admin-api/{collection}/{id}/revoke')
def revoke(collection:str,id:str,req:Request):
    if collection not in ('tokens','sessions'): raise HTTPException(404,'Unknown resource')
    with Session.begin() as db:
        authorized(req,db,permission='SESSION_REVOKE',admin=True); kind=collection[:-1]; x=required(db,kind,id); x['revoked']=True; save(db,kind,x); audit(db,req,kind+'.revoke',id); return {'ok':True}
async def credentials(req):
    data={k:v[0] for k,v in parse_qs((await req.body()).decode()).items()}
    header=req.headers.get('authorization','')
    if header.lower().startswith('basic '):
        try: data['client_id'],data['client_secret']=base64.b64decode(header[6:],validate=True).decode().split(':',1)
        except Exception: raise HTTPException(401,'Invalid client authentication')
    return data
def authenticate_client(db,data):
    c=get(db,'client',data.get('client_id','')); valid=False
    if c:
        try: valid=ph.verify(c['secretHash'],data.get('client_secret',''))
        except (VerifyMismatchError,InvalidHashError,TypeError): pass
    if not valid or not c or not c['active']: raise HTTPException(401,'invalid_client')
    return c
@app.post('/oauth/token')
async def token(req:Request):
    data=await credentials(req)
    with Session.begin() as db:
        if data.get('grant_type')=='authorization_code':
            c=get(db,'client',data.get('client_id','')); code=get(db,'authcode',digest(data.get('code','')))
            if not c or not c['active'] or 'oauth2_authorization_code_pkce' not in c.get('authenticationMethods',[]) or not code or code.get('used') or code['expiresAt']<time.time() or code['clientId']!=c['id'] or code['redirectUri']!=data.get('redirect_uri'): return JSONResponse({'error':'invalid_grant'},400)
            verifier=data.get('code_verifier',''); challenge=b64url(hashlib.sha256(verifier.encode()).digest())
            if len(verifier)<43 or len(verifier)>128 or not secrets.compare_digest(challenge,code['codeChallenge']): return JSONResponse({'error':'invalid_grant'},400)
            code['used']=True; save(db,'authcode',code); scopes=code['scopes']; req.state.actor=c['name']; req.state.authentication='OAuth 2.0 Authorization Code + PKCE'; grant='authorization_code'
        elif data.get('grant_type')=='client_credentials':
            c=authenticate_client(db,data); req.state.actor=c['name']; req.state.authentication='Client secret'
            if 'oauth2_client_credentials' not in c.get('authenticationMethods',['oauth2_client_credentials']): return JSONResponse({'error':'unauthorized_client'},401)
            scopes=data.get('scope',' '.join(c['scopes'])).split()
            if any(s not in c['scopes'] for s in scopes): return JSONResponse({'error':'invalid_scope'},400)
            grant='client_credentials'
        else: return JSONResponse({'error':'unsupported_grant_type'},400)
        value=secrets.token_urlsafe(48); save(db,'token',dict(id=uid(),clientId=c['id'],clientName=c['name'],hash=digest(value),scopes=scopes,grantType=grant,createdAt=now(),expiresAt=time.time()+3600,revoked=False)); audit(db,req,'token.issue',c['id'],{'grantType':grant})
        return {'access_token':value,'token_type':'Bearer','expires_in':3600,'scope':' '.join(scopes)}
@app.get('/oauth/authorize')
def authorize_code(req:Request):
    q=req.query_params
    with Session.begin() as db:
        user=authorized(req,db); c=get(db,'client',q.get('client_id','')); redirect=q.get('redirect_uri',''); requested=q.get('scope','').split() or (c.get('scopes',[]) if c else [])
        if q.get('response_type')!='code' or not c or not c['active'] or 'oauth2_authorization_code_pkce' not in c.get('authenticationMethods',[]) or redirect not in c.get('redirectUris',[]) or q.get('code_challenge_method')!='S256' or not q.get('code_challenge') or any(s not in c['scopes'] for s in requested): raise HTTPException(400,'Invalid authorization request')
        value=secrets.token_urlsafe(32); save(db,'authcode',dict(id=digest(value),clientId=c['id'],userId=user['id'],redirectUri=redirect,codeChallenge=q['code_challenge'],scopes=requested,createdAt=now(),expiresAt=time.time()+300,used=False)); audit(db,req,'authorization_code.issue',c['id'],{'userId':user['id']})
        return RedirectResponse(redirect+'?'+urlencode({'code':value,'state':q.get('state','')}),302)
@app.get('/oauth/callback')
def oauth_callback(req:Request): return {'code':req.query_params.get('code'),'state':req.query_params.get('state'),'next':'Exchange this one-time code at /oauth/token with the original PKCE verifier.'}
@app.post('/oauth/jwt')
async def issue_jwt(req:Request):
    data=await credentials(req)
    with Session.begin() as db:
        c=authenticate_client(db,data); req.state.actor=c['name']; req.state.authentication='Client secret'
        if 'jwt_bearer' not in c.get('authenticationMethods',[]): return JSONResponse({'error':'unauthorized_client'},401)
        scopes=data.get('scope',' '.join(c['scopes'])).split()
        if any(s not in c['scopes'] for s in scopes): return JSONResponse({'error':'invalid_scope'},400)
        value=jwt_token(c,scopes); audit(db,req,'jwt.issue',c['id']); return {'access_token':value,'token_type':'Bearer','expires_in':3600,'scope':' '.join(scopes)}
@app.post('/oauth/revoke')
async def oauth_revoke(req:Request):
    data=await credentials(req)
    with Session.begin() as db:
        c=authenticate_client(db,data)
        for t in rows(db,'token'):
            if t['clientId']==c['id'] and secrets.compare_digest(t['hash'],digest(data.get('token',''))): t['revoked']=True; save(db,'token',t)
    return {}

def user_auth(req,db,write=False):
    if req.url.path.startswith('/admin-api'): return authorized(req,db,admin=True,permission='USER_UPDATE')
    gate(db,'rest'); return authorized(req,db,scope='users:write' if write else 'users:read',permission='USER_UPDATE' if write else 'CUSTOMER_READ')
@app.get('/admin-api/users/{id}')
@app.get('/api/v1/users/{id}')
def user_get(id:str,req:Request):
    with Session() as db: user_auth(req,db); return api_user(req,db,required(db,'user',id))
@app.get('/api/v1/users')
def user_list(req:Request):
    with Session() as db: user_auth(req,db); return [api_user(req,db,u) for u in rows(db,'user') if not u['deleted']]
@app.post('/admin-api/users',status_code=201)
@app.post('/api/v1/users',status_code=201)
async def user_create(req:Request):
    data=await req.json()
    with Session.begin() as db:
        if req.url.path.startswith('/api/'): gate(db,'rest')
        authorized(req,db,scope='users:write',permission='USER_CREATE',admin=req.url.path.startswith('/admin-api')); created=create_user(db,req,data); return api_user(req,db,required(db,'user',created['id']))
@app.patch('/admin-api/users/{id}')
@app.patch('/api/v1/users/{id}')
async def user_update(id:str,req:Request):
    data=await req.json()
    with Session.begin() as db:
        user_auth(req,db,True)
        if 'roles' in data: authorized(req,db,scope='roles:write',permission='ACCESS_MANAGE')
        if any(k in data for k in ('active','locked','deleted')): authorized(req,db,scope='users:write',permission='USER_STATUS_MANAGE')
        update_user(db,req,id,data); return api_user(req,db,required(db,'user',id))
@app.delete('/admin-api/users/{id}')
@app.delete('/api/v1/users/{id}')
def user_delete(id:str,req:Request):
    with Session.begin() as db:
        user_auth(req,db,True); authorized(req,db,scope='users:write',permission='USER_STATUS_MANAGE'); update_user(db,req,id,{'deleted':True,'active':False}); return Response(status_code=204)
@app.put('/api/v1/users/{id}/roles')
async def assign_roles(id:str,req:Request):
    data=await req.json()
    with Session.begin() as db:
        gate(db,'rest'); authorized(req,db,scope='roles:write',permission='ACCESS_MANAGE'); update_user(db,req,id,{'roles':data.get('roles',[])}); return api_user(req,db,required(db,'user',id))
@app.get('/api/v1/users/{id}/permissions')
def permissions(id:str,req:Request):
    with Session() as db: gate(db,'rest'); authorized(req,db,scope='roles:read',permission='ACCESS_MANAGE'); require_read_attribute(req,'permissions'); return {'userId':id,'permissions':effective(db,required(db,'user',id))}
@app.get('/api/v1/roles')
@app.get('/api/v1/groups')
def roles_groups(req:Request):
    is_role=req.url.path.endswith('/roles')
    with Session() as db: gate(db,'rest'); authorized(req,db,scope='roles:read' if is_role else 'groups:read',permission='ACCESS_MANAGE'); return rows(db,'role' if is_role else 'group')
@app.post('/admin-api/users/{id}/reset-password')
async def reset_password(id:str,req:Request):
    data=await req.json(); password=data.get('password','')
    if len(password)<10: raise HTTPException(400,'Password must have at least 10 characters')
    with Session.begin() as db:
        authorized(req,db,admin=True,permission='USER_PASSWORD_RESET'); u=required(db,'user',id); u['passwordHash']=ph.hash(password); save(db,'user',u); revoke_sessions(db,id); audit(db,req,'user.password_reset',id); return {'ok':True}
@app.post('/admin-api/groups',status_code=201)
async def group_create(req:Request):
    data=await req.json()
    with Session.begin() as db:
        authorized(req,db,admin=True,permission='ACCESS_MANAGE'); validate_roles(db,data.get('roles',[]))
        for id in data.get('members',[]): required(db,'user',id)
        g=dict(id=uid(),displayName=data.get('displayName','New group'),roles=data.get('roles',[]),permissions=[],members=data.get('members',[])); save(db,'group',g); audit(db,req,'group.create',g['id']); return g
@app.patch('/admin-api/groups/{id}')
async def group_update(id:str,req:Request):
    data=await req.json()
    with Session.begin() as db:
        authorized(req,db,admin=True,permission='ACCESS_MANAGE'); group=required(db,'group',id)
        if 'roles' in data: validate_roles(db,data['roles']); group['roles']=data['roles']
        if 'members' in data:
            if not isinstance(data['members'],list): raise HTTPException(400,'members must be a list')
            [required(db,'user',member) for member in data['members']]; group['members']=list(dict.fromkeys(data['members']))
        if 'displayName' in data:
            if not str(data['displayName']).strip(): raise HTTPException(400,'Group name is required')
            group['displayName']=str(data['displayName']).strip()[:100]
        save(db,'group',group); audit(db,req,'group.update',id,{'fields':sorted(data)}); return group
@app.delete('/admin-api/groups/{id}',status_code=204)
def group_delete(id:str,req:Request):
    with Session.begin() as db:
        authorized(req,db,admin=True,permission='ACCESS_MANAGE'); required(db,'group',id); db.delete(db.get(Record,'group:'+id)); audit(db,req,'group.delete',id); return Response(status_code=204)
@app.post('/admin-api/roles',status_code=201)
async def role_create(req:Request):
    data=await req.json(); name=str(data.get('name','')).strip(); permissions=data.get('permissions',[])
    if not name: raise HTTPException(400,'Role name is required')
    with Session.begin() as db:
        authorized(req,db,admin=True,permission='ACCESS_MANAGE'); validate_permissions(db,permissions); role=dict(id=uid(),name=name[:100],description=str(data.get('description',''))[:240],permissions=permissions,system=False,createdAt=now()); save(db,'role',role); audit(db,req,'role.create',role['id'],{'permissions':permissions}); return role
@app.patch('/admin-api/roles/{id}')
async def role_update(id:str,req:Request):
    data=await req.json()
    with Session.begin() as db:
        authorized(req,db,admin=True,permission='ACCESS_MANAGE'); role=required(db,'role',id)
        if id in {x[0] for x in ROLE_DEFS}: raise HTTPException(409,'Built-in roles are read-only; create a custom role instead')
        if 'permissions' in data: validate_permissions(db,data['permissions']); role['permissions']=data['permissions']
        if 'name' in data:
            if not str(data['name']).strip(): raise HTTPException(400,'Role name is required')
            role['name']=str(data['name']).strip()[:100]
        if 'description' in data: role['description']=str(data['description'])[:240]
        save(db,'role',role); audit(db,req,'role.update',id,{'fields':sorted(data)}); return role
@app.delete('/admin-api/roles/{id}',status_code=204)
def role_delete(id:str,req:Request):
    with Session.begin() as db:
        authorized(req,db,admin=True,permission='ACCESS_MANAGE'); required(db,'role',id)
        if id in {x[0] for x in ROLE_DEFS}: raise HTTPException(409,'Built-in roles cannot be deleted')
        if any(id in u.get('roles',[]) for u in rows(db,'user')) or any(id in g.get('roles',[]) for g in rows(db,'group')): raise HTTPException(409,'Remove this role from users and groups before deletion')
        db.delete(db.get(Record,'role:'+id)); audit(db,req,'role.delete',id); return Response(status_code=204)
@app.post('/admin-api/permissions',status_code=201)
async def permission_create(req:Request):
    data=await req.json(); id=str(data.get('id','')).strip().upper(); name=str(data.get('name','')).strip()
    if not re.fullmatch(r'[A-Z][A-Z0-9_]{2,63}',id): raise HTTPException(400,'Permission key must use 3–64 uppercase letters, numbers or underscores')
    with Session.begin() as db:
        authorized(req,db,admin=True,permission='ACCESS_MANAGE')
        if id in permission_ids(db): raise HTTPException(409,'Permission already exists')
        permission=dict(id=id,name=name[:100] or id.replace('_',' ').title(),description=str(data.get('description',''))[:240],system=False,createdAt=now()); save(db,'permission',permission); audit(db,req,'permission.create',id); return permission

WEBHOOK_EVENTS={'user.created','user.updated','user.deleted','user.disabled','payment.created','payment.approved','payment.rejected','client.revoked'}
def public_webhook(value): return {k:v for k,v in value.items() if k not in ('secretEncrypted',)}
def emit_webhooks(db,event,payload,only_id=None):
    if event not in WEBHOOK_EVENTS: return []
    results=[]
    for hook in rows(db,'webhook'):
        if not hook.get('active',True) or event not in hook.get('events',[]) or (only_id and hook['id']!=only_id): continue
        delivery_id=uid(); body=json.dumps({'id':delivery_id,'event':event,'createdAt':now(),'data':payload},separators=(',',':')).encode(); secret=decrypt_secret(hook['secretEncrypted']); signature='sha256='+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest(); status=0; error=None
        try:
            url=safe_sso_url(hook['url'],resolve=True); request=urllib.request.Request(url,data=body,method='POST',headers={'Content-Type':'application/json','User-Agent':'Identity-API-Lab/1.5','X-Identity-Event':event,'X-Identity-Delivery':delivery_id,'X-Identity-Signature':signature})
            with urllib.request.urlopen(request,timeout=10) as response: status=response.status; response.read(65536)
        except Exception as exc: error=type(exc).__name__
        record=dict(id=delivery_id,webhookId=hook['id'],event=event,url=hook['url'],status=status,delivered=200<=status<300,error=error,createdAt=now()); save(db,'webhook_delivery',record); results.append(record)
    return results
@app.get('/admin-api/webhooks')
def webhook_list(req:Request):
    with Session() as db: authorized(req,db,admin=True,permission='API_MANAGE'); return [public_webhook(x) for x in rows(db,'webhook')]
@app.post('/admin-api/webhooks',status_code=201)
async def webhook_create(req:Request):
    data=await req.json(); events=data.get('events',[]); url=safe_sso_url(data.get('url'))
    if not isinstance(events,list) or not events or any(x not in WEBHOOK_EVENTS for x in events): raise HTTPException(400,'Select one or more supported webhook events')
    secret=secrets.token_urlsafe(32)
    with Session.begin() as db:
        gate(db,'webhooks'); authorized(req,db,admin=True,permission='API_MANAGE'); hook=dict(id=uid(),name=str(data.get('name','Webhook'))[:100],url=url,events=sorted(set(events)),active=bool(data.get('active',True)),secretEncrypted=encrypt_secret(secret),createdAt=now()); save(db,'webhook',hook); audit(db,req,'webhook.create',hook['id']); return {**public_webhook(hook),'secret':secret}
@app.post('/admin-api/webhooks/{id}/test')
def webhook_test(id:str,req:Request):
    with Session.begin() as db:
        gate(db,'webhooks'); authorized(req,db,admin=True,permission='API_MANAGE'); required(db,'webhook',id); result=emit_webhooks(db,'user.updated',{'id':'webhook-test','displayName':'Webhook verification'},only_id=id); audit(db,req,'webhook.test',id); return result[0]
@app.delete('/admin-api/webhooks/{id}',status_code=204)
def webhook_delete(id:str,req:Request):
    with Session.begin() as db: authorized(req,db,admin=True,permission='API_MANAGE'); required(db,'webhook',id); db.delete(db.get(Record,'webhook:'+id)); audit(db,req,'webhook.delete',id); return Response(status_code=204)
@app.get('/admin-api/webhook-deliveries')
def webhook_deliveries(req:Request):
    with Session() as db: authorized(req,db,admin=True,permission='AUDIT_READ'); return sorted(rows(db,'webhook_delivery'),key=lambda x:x['createdAt'],reverse=True)[:500]

def safe_sftp_host(host,port):
    host=str(host or '').strip().lower(); private=os.getenv('ALLOW_PRIVATE_SFTP','false').lower()=='true'
    if not re.fullmatch(r'[a-z0-9.-]+|[0-9a-f:]+',host) or not 1<=port<=65535: raise HTTPException(400,'Valid SFTP host and port required')
    try: addresses=[ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)]
    except socket.gaierror as exc: raise HTTPException(400,'SFTP host could not be resolved') from exc
    if not private and any(x.is_private or x.is_loopback or x.is_link_local or x.is_multicast or x.is_reserved or x.is_unspecified for x in addresses): raise HTTPException(400,'Private SFTP hosts require ALLOW_PRIVATE_SFTP=true')
    return host
def public_sftp(value): return {k:v for k,v in value.items() if k not in ('passwordEncrypted',)}
def open_sftp(connector):
    host=connector['host']; port=connector['port']; key_type,key_data=connector['knownHostKey'].split(None,1); classes={'ssh-ed25519':paramiko.Ed25519Key,'ssh-rsa':paramiko.RSAKey,'ecdsa-sha2-nistp256':paramiko.ECDSAKey}
    if key_type not in classes: raise HTTPException(400,'Unsupported SFTP host key type')
    try: key=classes[key_type](data=base64.b64decode(key_data.encode(),validate=True))
    except Exception as exc: raise HTTPException(400,'Invalid SFTP known host key') from exc
    client=paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.RejectPolicy()); client.get_host_keys().add(host if port==22 else f'[{host}]:{port}',key_type,key)
    try: client.connect(hostname=host,port=port,username=connector['username'],password=decrypt_secret(connector['passwordEncrypted']),look_for_keys=False,allow_agent=False,timeout=10,banner_timeout=10,auth_timeout=10); return client,client.open_sftp()
    except Exception as exc: client.close(); raise HTTPException(502,'SFTP connection failed') from exc
@app.get('/admin-api/sftp-connectors')
def sftp_list(req:Request):
    with Session() as db: authorized(req,db,admin=True,permission='API_MANAGE'); return [public_sftp(x) for x in rows(db,'sftp')]
@app.post('/admin-api/sftp-connectors',status_code=201)
async def sftp_create(req:Request):
    data=await req.json()
    try: port=int(data.get('port',22))
    except (TypeError,ValueError): raise HTTPException(400,'Valid SFTP port required')
    host=safe_sftp_host(data.get('host'),port); remote_path=str(data.get('remotePath','/users.csv'))
    if '..' in remote_path.split('/') or not remote_path.endswith('.csv') or len(remote_path)>512: raise HTTPException(400,'Remote path must identify a CSV file without parent traversal')
    if not data.get('username') or not data.get('password') or not data.get('knownHostKey'): raise HTTPException(400,'Username, password and pinned known host key are required')
    with Session.begin() as db:
        gate(db,'csvsftp'); authorized(req,db,admin=True,permission='API_MANAGE'); connector=dict(id=uid(),name=str(data.get('name','SFTP connector'))[:100],host=host,port=port,username=str(data['username'])[:100],passwordEncrypted=encrypt_secret(str(data['password'])),knownHostKey=str(data['knownHostKey'])[:4096],remotePath=remote_path,createdAt=now()); save(db,'sftp',connector); audit(db,req,'sftp.create',connector['id']); return public_sftp(connector)
@app.post('/admin-api/sftp-connectors/{id}/{action}')
def sftp_transfer(id:str,action:str,req:Request):
    if action not in ('push','pull','test'): raise HTTPException(404,'Unknown SFTP action')
    with Session.begin() as db:
        gate(db,'csvsftp'); authorized(req,db,admin=True,permission='API_MANAGE'); connector=required(db,'sftp',id); client,sftp=open_sftp(connector)
        try:
            count=0
            if action=='push':
                content=users_csv(req,db).encode(); handle=sftp.file(connector['remotePath'],'wb'); handle.write(content); handle.close(); count=len([x for x in rows(db,'user') if not x['deleted']])
            elif action=='pull':
                handle=sftp.file(connector['remotePath'],'rb'); content=handle.read(1048577); handle.close()
                if len(content)>1048576: raise HTTPException(413,'Remote CSV exceeds 1 MiB')
                count=len(import_users_csv(req,db,content.decode('utf-8-sig')))
            audit(db,req,'sftp.'+action,id,{'records':count}); return {'status':'connected' if action=='test' else 'completed','action':action,'records':count}
        finally: sftp.close(); client.close()
@app.delete('/admin-api/sftp-connectors/{id}',status_code=204)
def sftp_delete(id:str,req:Request):
    with Session.begin() as db: authorized(req,db,admin=True,permission='API_MANAGE'); required(db,'sftp',id); db.delete(db.get(Record,'sftp:'+id)); audit(db,req,'sftp.delete',id); return Response(status_code=204)

SCIM_USER='urn:ietf:params:scim:schemas:core:2.0:User'
SCIM_GROUP='urn:ietf:params:scim:schemas:core:2.0:Group'
SCIM_ENTERPRISE='urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'
def scim_user(db,u,req=None):
    readable=set(getattr(req.state,'apiClient',{}).get('readAttributes',READABLE_USER_ATTRIBUTES)) if req and getattr(req.state,'apiClient',None) else set(READABLE_USER_ATTRIBUTES)
    result={'schemas':[SCIM_USER,SCIM_ENTERPRISE],'id':u['id'],'meta':{'resourceType':'User','location':'/scim/v2/Users/'+u['id']}}
    if 'username' in readable: result['userName']=u['username']
    if 'displayName' in readable: result['displayName']=u['displayName']
    if {'firstName','lastName'}&readable: result['name']={**({'givenName':u['firstName']} if 'firstName' in readable else {}),**({'familyName':u['lastName']} if 'lastName' in readable else {})}
    if 'active' in readable: result['active']=u['active'] and not u['deleted']
    if 'jobTitle' in readable: result['title']=u['jobTitle']
    if 'email' in readable: result['emails']=[{'value':u['email'],'primary':True,'type':'work'}]
    if {'country','city'}&readable: result['addresses']=[{**({'country':u['country']} if 'country' in readable else {}),**({'locality':u['city']} if 'city' in readable else {}),'type':'work'}]
    if 'department' in readable: result[SCIM_ENTERPRISE]={'department':u['department']}
    if 'groups' in readable: result['groups']=[{'value':g['id'],'display':g['displayName']} for g in rows(db,'group') if u['id'] in g['members']]
    if 'createdAt' in readable: result['meta']['created']=u['createdAt']
    if 'updatedAt' in readable: result['meta']['lastModified']=u['updatedAt']
    return result
def scim_group(g): return {'schemas':[SCIM_GROUP],'id':g['id'],'displayName':g['displayName'],'members':[{'value':x} for x in g['members']],'meta':{'resourceType':'Group','location':'/scim/v2/Groups/'+g['id']}}
def scim_input(data):
    out={}; mapping={'userName':'username','displayName':'displayName','active':'active','title':'jobTitle','password':'password'}
    for k,v in mapping.items():
        if k in data: out[v]=data[k]
    if 'name' in data: out.update(firstName=data['name'].get('givenName',''),lastName=data['name'].get('familyName',''))
    if 'emails' in data: out['email']=next((e.get('value','') for e in data['emails'] if e.get('primary')),data['emails'][0].get('value','') if data['emails'] else '')
    if 'addresses' in data: out.update(country=data['addresses'][0].get('country','') if data['addresses'] else '',city=data['addresses'][0].get('locality','') if data['addresses'] else '')
    if SCIM_ENTERPRISE in data: out['department']=data[SCIM_ENTERPRISE].get('department','')
    return out
@app.exception_handler(HTTPException)
async def http_error(req,exc):
    if req.url.path.startswith('/scim/'):
        return JSONResponse({'schemas':['urn:ietf:params:scim:api:messages:2.0:Error'],'status':str(exc.status_code),'detail':exc.detail},exc.status_code,headers=exc.headers,media_type='application/scim+json')
    return JSONResponse({'detail':exc.detail},exc.status_code,headers=exc.headers)
@app.exception_handler(IntegrityError)
async def conflict_error(req,exc):
    return await http_error(req,HTTPException(409,'Resource uniqueness conflict'))
@app.exception_handler(json.JSONDecodeError)
async def invalid_json(req,exc):
    return await http_error(req,HTTPException(400,'Valid JSON body required'))
@app.get('/scim/v2/ServiceProviderConfig')
def service_config(req:Request):
    with Session() as db: gate(db,'scim'); authorized(req,db,scope='users:read',permission='CUSTOMER_READ')
    return {'schemas':['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],'patch':{'supported':True},'bulk':{'supported':False,'maxOperations':0,'maxPayloadSize':0},'filter':{'supported':True,'maxResults':200},'changePassword':{'supported':False},'sort':{'supported':False},'etag':{'supported':False},'authenticationSchemes':[{'type':'oauthbearertoken','name':'OAuth bearer token','description':'Scoped client credentials tokens','primary':True},{'type':'oauth','name':'API key','description':'X-API-Key header using a scoped client key','primary':False},{'type':'httpbasic','name':'HTTP Basic','description':'Scoped client ID and secret','primary':False}]}
@app.get('/scim/v2/ResourceTypes')
def resource_types(req:Request):
    with Session() as db: gate(db,'scim'); authorized(req,db,scope='users:read',permission='CUSTOMER_READ')
    rs=[{'schemas':['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],'id':name,'name':name,'endpoint':'/'+name+'s','schema':schema} for name,schema in [('User',SCIM_USER),('Group',SCIM_GROUP)]]
    return {'schemas':['urn:ietf:params:scim:api:messages:2.0:ListResponse'],'totalResults':2,'Resources':rs}
@app.get('/scim/v2/Schemas')
def schemas(req:Request):
    with Session() as db: gate(db,'scim'); authorized(req,db,scope='users:read',permission='CUSTOMER_READ')
    attrs=lambda names:[{'name':n,'type':t,'multiValued':multi,'required':n=='userName','caseExact':False,'mutability':'readWrite','returned':'default','uniqueness':'server' if n=='userName' else 'none'} for n,t,multi in names]
    resources=[{'schemas':['urn:ietf:params:scim:schemas:core:2.0:Schema'],'id':SCIM_USER,'name':'User','attributes':attrs([('userName','string',False),('displayName','string',False),('active','boolean',False),('name','complex',False),('emails','complex',True),('addresses','complex',True),('title','string',False)])},{'schemas':['urn:ietf:params:scim:schemas:core:2.0:Schema'],'id':SCIM_GROUP,'name':'Group','attributes':attrs([('displayName','string',False),('members','complex',True)])},{'schemas':['urn:ietf:params:scim:schemas:core:2.0:Schema'],'id':SCIM_ENTERPRISE,'name':'EnterpriseUser','attributes':attrs([('department','string',False)])}]
    return {'schemas':['urn:ietf:params:scim:api:messages:2.0:ListResponse'],'totalResults':len(resources),'Resources':resources}
@app.api_route('/scim/v2/{resource}',methods=['GET','POST'])
@app.api_route('/scim/v2/{resource}/{id}',methods=['GET','PUT','PATCH','DELETE'])
async def scim(req:Request,resource:str,id:str=None):
    if resource not in ('Users','Groups'): raise HTTPException(404,'Resource not found')
    users=resource=='Users'; kind='user' if users else 'group'; write=req.method!='GET'; data=await req.json() if req.method in ('POST','PUT','PATCH') else {}
    with Session.begin() as db:
        gate(db,'scim'); authorized(req,db,scope=('users' if users else 'groups')+(':write' if write else ':read'),permission=('USER_UPDATE' if users else 'ACCESS_MANAGE') if write else 'CUSTOMER_READ')
        render=lambda x:scim_user(db,x,req) if users else scim_group(x)
        if req.method=='GET':
            if id:
                obj=required(db,kind,id)
                if obj.get('deleted'): raise HTTPException(404,'User not found')
                result=render(obj)
            else:
                items=[render(x) for x in rows(db,kind) if not x.get('deleted')]; f=req.query_params.get('filter')
                if f:
                    m=re.fullmatch(r'(userName|displayName|active|id)\s+(eq|co|sw)\s+("[^"\\]*"|true|false)',f,re.I)
                    if not m: raise HTTPException(400,'Unsupported filter. Supported: userName/displayName/id eq/co/sw, active eq')
                    key,op,raw=m.groups(); key={'username':'userName','displayname':'displayName','active':'active','id':'id'}[key.lower()]; op=op.lower(); val=json.loads(raw)
                    if key=='active' and (op!='eq' or not isinstance(val,bool)): raise HTTPException(400,'Invalid active filter')
                    items=[x for x in items if (str(x.get(key,'')).lower()==str(val).lower() if op=='eq' else str(val).lower() in str(x.get(key,'')).lower() if op=='co' else str(x.get(key,'')).lower().startswith(str(val).lower()))]
                try: start=max(1,int(req.query_params.get('startIndex',1))); count=min(200,max(0,int(req.query_params.get('count',100))))
                except ValueError: raise HTTPException(400,'Invalid pagination')
                result={'schemas':['urn:ietf:params:scim:api:messages:2.0:ListResponse'],'totalResults':len(items),'startIndex':start,'itemsPerPage':len(items[start-1:start-1+count]),'Resources':items[start-1:start-1+count]}
            return JSONResponse(result,media_type='application/scim+json')
        if req.method=='POST':
            if users:
                authorized(req,db,scope='users:write',permission='USER_CREATE'); result=render(create_user(db,req,scim_input(data)))
            else:
                members=[m['value'] for m in data.get('members',[])]; [required(db,'user',m) for m in members]
                obj=dict(id=uid(),displayName=data.get('displayName',''),roles=[],permissions=[],members=members); save(db,'group',obj); audit(db,req,'group.create',obj['id']); result=render(obj)
            return JSONResponse(result,201,headers={'Location':result['meta']['location']},media_type='application/scim+json')
        obj=required(db,kind,id)
        if req.method=='DELETE':
            if users: authorized(req,db,scope='users:write',permission='USER_STATUS_MANAGE'); update_user(db,req,id,{'deleted':True,'active':False})
            else: db.delete(db.get(Record,'group:'+id)); audit(db,req,'group.delete',id)
            return Response(status_code=204)
        if req.method=='PATCH':
            if data.get('schemas')!=['urn:ietf:params:scim:api:messages:2.0:PatchOp'] or not isinstance(data.get('Operations'),list) or not data['Operations']: raise HTTPException(400,'Invalid PatchOp document')
            patch={}
            for operation in data['Operations']:
                op=str(operation.get('op','')).lower(); path=operation.get('path'); value=operation.get('value')
                if op not in ('add','replace','remove'): raise HTTPException(400,'Unsupported patch operation')
                if not path:
                    if not isinstance(value,dict) or op=='remove': raise HTTPException(400,'Patch path required')
                    patch.update(value); continue
                if path in ('id','userName','meta','schemas'): raise HTTPException(400,'Attribute is immutable')
                if path not in ('active','displayName','title','emails','addresses','name','name.givenName','name.familyName',SCIM_ENTERPRISE+':department','members'): raise HTTPException(400,'Unsupported patch path')
                if op=='remove' and path=='active': raise HTTPException(400,'active cannot be removed')
                if path=='members' and not users:
                    prior=[{'value':x} for x in obj['members']]
                    if op=='add': value=prior+(value if isinstance(value,list) else [value])
                    elif op=='remove': value=[]
                if path.startswith('name.'):
                    patch.setdefault('name',{'givenName':obj.get('firstName',''),'familyName':obj.get('lastName','')})[path.split('.')[1]]='' if op=='remove' else value
                elif path==SCIM_ENTERPRISE+':department': patch[SCIM_ENTERPRISE]={'department':'' if op=='remove' else value}
                else: patch[path]=([] if path in ('emails','addresses','members') else '') if op=='remove' else value
            data=patch
        if users:
            mapped=scim_input(data)
            if 'active' in mapped: authorized(req,db,scope='users:write',permission='USER_STATUS_MANAGE')
            result=render(update_user(db,req,id,mapped))
        else:
            if 'members' in data:
                members=[m['value'] for m in data['members']]; [required(db,'user',m) for m in members]; obj['members']=list(dict.fromkeys(members))
            if 'displayName' in data: obj['displayName']=data['displayName']
            save(db,'group',obj); audit(db,req,'group.update',id); result=render(obj)
        return JSONResponse(result,media_type='application/scim+json')

SCIM11_USER='urn:scim:schemas:core:1.0'
def scim11_user(db,u,req):
    current=scim_user(db,u,req)
    result={k:v for k,v in current.items() if k not in ('schemas',SCIM_ENTERPRISE)}
    result['schemas']=[SCIM11_USER]; result['meta']['location']='/scim/v1/Users/'+u['id']
    if SCIM_ENTERPRISE in current: result['department']=current[SCIM_ENTERPRISE].get('department','')
    return result
@app.api_route('/scim/v1/Users',methods=['GET','POST'])
@app.api_route('/scim/v1/Users/{id}',methods=['GET','PUT','PATCH','DELETE'])
async def scim11(req:Request,id:str=None):
    write=req.method!='GET'; data=await req.json() if req.method in ('POST','PUT','PATCH') else {}
    with Session.begin() as db:
        gate(db,'scim11'); authorized(req,db,scope='users:'+('write' if write else 'read'),permission='USER_UPDATE' if write else 'CUSTOMER_READ')
        if req.method=='GET':
            if id: return JSONResponse(scim11_user(db,required(db,'user',id),req),media_type='application/json')
            items=[scim11_user(db,u,req) for u in rows(db,'user') if not u['deleted']]
            start=max(1,int(req.query_params.get('startIndex',1))); count=min(200,max(0,int(req.query_params.get('count',100)))); page=items[start-1:start-1+count]
            return {'schemas':['urn:scim:schemas:core:1.0'],'totalResults':len(items),'startIndex':start,'itemsPerPage':len(page),'Resources':page}
        if req.method=='POST':
            authorized(req,db,scope='users:write',permission='USER_CREATE'); result=scim11_user(db,create_user(db,req,scim_input(data)),req)
            return JSONResponse(result,201,headers={'Location':result['meta']['location']})
        if req.method=='DELETE':
            authorized(req,db,scope='users:write',permission='USER_STATUS_MANAGE'); update_user(db,req,id,{'deleted':True,'active':False}); return Response(status_code=204)
        mapped=scim_input(data)
        if 'department' in data: mapped['department']=data['department']
        if 'active' in mapped: authorized(req,db,scope='users:write',permission='USER_STATUS_MANAGE')
        return scim11_user(db,update_user(db,req,id,mapped),req)

ODATA_FIELDS={'id','username','displayName','firstName','lastName','email','department','jobTitle','country','city','active','locked','createdAt','updatedAt'}
def odata_user(req,db,u,fields=None):
    item=api_user(req,db,u); selected=(set(fields)&ODATA_FIELDS) if fields else ODATA_FIELDS
    return {k:v for k,v in item.items() if k in selected or k=='id'}
@app.get('/odata/v4/$metadata')
def odata_metadata(req:Request):
    with Session() as db: gate(db,'odata'); authorized(req,db,scope='users:read',permission='CUSTOMER_READ')
    props=''.join(f'<Property Name="{name}" Type="Edm.{"Boolean" if name in ("active","locked") else "String"}" Nullable="false"/>' for name in sorted(ODATA_FIELDS))
    xml=f'<?xml version="1.0" encoding="utf-8"?><edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx"><edmx:DataServices><Schema Namespace="IdentityLab" xmlns="http://docs.oasis-open.org/odata/ns/edm"><EntityType Name="User"><Key><PropertyRef Name="id"/></Key>{props}</EntityType><EntityContainer Name="Container"><EntitySet Name="Users" EntityType="IdentityLab.User"/></EntityContainer></Schema></edmx:DataServices></edmx:Edmx>'
    return Response(xml,media_type='application/xml')
@app.api_route('/odata/v4/Users',methods=['GET','POST'])
@app.api_route('/odata/v4/Users({id})',methods=['GET','PATCH','DELETE'])
async def odata_users(req:Request,id:str=None):
    write=req.method!='GET'; data=await req.json() if req.method in ('POST','PATCH') else {}
    with Session.begin() as db:
        gate(db,'odata'); authorized(req,db,scope='users:'+('write' if write else 'read'),permission='USER_UPDATE' if write else 'CUSTOMER_READ')
        fields=[x.strip() for x in req.query_params.get('$select','').split(',') if x.strip()]
        if any(x not in ODATA_FIELDS for x in fields): raise HTTPException(400,'Unknown $select property')
        if req.method=='GET' and id: return {'@odata.context':'$metadata#Users/$entity',**odata_user(req,db,required(db,'user',id),fields)}
        if req.method=='GET':
            items=[u for u in rows(db,'user') if not u['deleted']]; query=req.query_params.get('$filter')
            if query:
                m=re.fullmatch(r'(username|displayName|email|department|country|active)\s+(eq|ne)\s+(?:\'([^\']*)\'|(true|false))',query,re.I)
                if not m: raise HTTPException(400,'Unsupported $filter expression')
                field,op,text_value,bool_value=m.groups(); value=(bool_value.lower()=='true') if bool_value else text_value
                items=[u for u in items if ((u.get(field)==value) if op.lower()=='eq' else (u.get(field)!=value))]
            try: skip=max(0,int(req.query_params.get('$skip',0))); top=min(200,max(0,int(req.query_params.get('$top',100))))
            except ValueError: raise HTTPException(400,'Invalid OData pagination')
            result={'@odata.context':'$metadata#Users','value':[odata_user(req,db,u,fields) for u in items[skip:skip+top]]}
            if req.query_params.get('$count','false').lower()=='true': result['@odata.count']=len(items)
            return result
        if req.method=='POST':
            authorized(req,db,scope='users:write',permission='USER_CREATE'); created=create_user(db,req,data)
            return JSONResponse({'@odata.context':'$metadata#Users/$entity',**odata_user(req,db,created)},201,headers={'Location':f'/odata/v4/Users({created["id"]})'})
        if req.method=='DELETE':
            authorized(req,db,scope='users:write',permission='USER_STATUS_MANAGE'); update_user(db,req,id,{'deleted':True,'active':False}); return Response(status_code=204)
        return {'@odata.context':'$metadata#Users/$entity',**odata_user(req,db,update_user(db,req,id,data))}

def rpc_result(req,db,method,params):
    if method=='users.list': authorized(req,db,scope='users:read',permission='CUSTOMER_READ'); return [api_user(req,db,u) for u in rows(db,'user') if not u['deleted']]
    if method=='users.get': authorized(req,db,scope='users:read',permission='CUSTOMER_READ'); return api_user(req,db,required(db,'user',params.get('id','')))
    if method=='users.create': authorized(req,db,scope='users:write',permission='USER_CREATE'); return api_user(req,db,create_user(db,req,params))
    if method=='users.update': authorized(req,db,scope='users:write',permission='USER_UPDATE'); values=dict(params); id=values.pop('id',''); return api_user(req,db,update_user(db,req,id,values))
    if method=='users.disable': authorized(req,db,scope='users:write',permission='USER_STATUS_MANAGE'); return api_user(req,db,update_user(db,req,params.get('id',''),{'active':False}))
    raise HTTPException(404,'JSON-RPC method not found')
@app.post('/jsonrpc')
async def jsonrpc(req:Request):
    document=await req.json(); calls=document if isinstance(document,list) else [document]
    if not calls or len(calls)>20: raise HTTPException(400,'JSON-RPC batch must contain 1–20 calls')
    replies=[]
    with Session.begin() as db:
        gate(db,'jsonrpc')
        for call in calls:
            rpc_id=call.get('id') if isinstance(call,dict) else None
            if not isinstance(call,dict) or call.get('jsonrpc')!='2.0' or not isinstance(call.get('method'),str) or not isinstance(call.get('params',{}),dict): replies.append({'jsonrpc':'2.0','id':rpc_id,'error':{'code':-32600,'message':'Invalid Request'}}); continue
            try: replies.append({'jsonrpc':'2.0','id':rpc_id,'result':rpc_result(req,db,call['method'],call.get('params',{}))})
            except HTTPException as exc: replies.append({'jsonrpc':'2.0','id':rpc_id,'error':{'code':-32601 if exc.status_code==404 else -32000-exc.status_code,'message':str(exc.detail)}})
    return replies if isinstance(document,list) else replies[0]

CSV_FIELDS=['username','displayName','firstName','lastName','email','department','jobTitle','country','city','active']
def users_csv(req,db):
    output=io.StringIO(newline=''); writer=csv.DictWriter(output,fieldnames=['id']+CSV_FIELDS); writer.writeheader()
    for user in rows(db,'user'):
        if not user['deleted']:
            visible=api_user(req,db,user); writer.writerow({key:visible.get(key,'') for key in ['id']+CSV_FIELDS})
    return output.getvalue()
def import_users_csv(req,db,text):
    reader=csv.DictReader(io.StringIO(text)); expected=set(CSV_FIELDS)
    if not reader.fieldnames or 'username' not in reader.fieldnames or any(x not in expected for x in reader.fieldnames): raise HTTPException(400,'CSV header contains unsupported fields')
    records=list(reader)
    if not records or len(records)>500: raise HTTPException(400,'CSV import must contain 1–500 users')
    created=[]
    for row in records:
        values={k:v for k,v in row.items() if v not in (None,'')}
        if 'active' in values:
            if values['active'].lower() not in ('true','false'): raise HTTPException(400,'CSV active values must be true or false')
            values['active']=values['active'].lower()=='true'
        created.append(api_user(req,db,create_user(db,req,values)))
    return created
@app.get('/api/v1/csv/users')
def csv_export(req:Request):
    with Session() as db: gate(db,'csvsftp'); authorized(req,db,scope='users:read',permission='CUSTOMER_READ'); text=users_csv(req,db)
    return Response(text,media_type='text/csv',headers={'Content-Disposition':'attachment; filename="identity-users.csv"'})
@app.post('/api/v1/csv/users',status_code=201)
async def csv_import(req:Request):
    text=(await req.body()).decode('utf-8-sig')
    with Session.begin() as db: gate(db,'csvsftp'); authorized(req,db,scope='users:write',permission='USER_CREATE'); created=import_users_csv(req,db,text); return {'created':len(created),'users':created}

GQL=build_schema('''
type User { id: ID!, username: String, displayName: String, email: String, active: Boolean, locked: Boolean, department: String, country: String, roles: [String!], permissions: [String!] }
type Role { id: ID!, name: String!, permissions: [String!]! }
type Query { users: [User!]!, user(id: ID!): User, effectivePermissions(userId: ID!): [String!]!, roles: [Role!]! }
type Mutation { setUserActive(id: ID!, active: Boolean!): User!, assignRoles(userId: ID!, roleIds: [ID!]!): User! }
''')
def gql_resolver(field,scope,permission,callback):
    def resolve(source,info,**args):
        req,db=info.context; authorized(req,db,scope=scope,permission=permission); return callback(req,db,args)
    GQL.type_map['Mutation' if field in ('setUserActive','assignRoles') else 'Query'].fields[field].resolve=resolve
gql_resolver('users','users:read','CUSTOMER_READ',lambda r,d,a:[api_user(r,d,u) for u in rows(d,'user') if not u['deleted']])
gql_resolver('user','users:read','CUSTOMER_READ',lambda r,d,a:api_user(r,d,required(d,'user',a['id'])))
def gql_effective_permissions(req,db,args): require_read_attribute(req,'permissions'); return effective(db,required(db,'user',args['userId']))
gql_resolver('effectivePermissions','roles:read','ACCESS_MANAGE',gql_effective_permissions)
gql_resolver('roles','roles:read','ACCESS_MANAGE',lambda r,d,a:rows(d,'role'))
def gql_update(req,db,args,values): update_user(db,req,args.get('id') or args.get('userId'),values); return api_user(req,db,required(db,'user',args.get('id') or args.get('userId')))
gql_resolver('setUserActive','users:write','USER_STATUS_MANAGE',lambda r,d,a:gql_update(r,d,a,{'active':a['active']}))
gql_resolver('assignRoles','roles:write','ACCESS_MANAGE',lambda r,d,a:gql_update(r,d,a,{'roles':a['roleIds']}))
def gql_permissions(source,info):
    req,db=info.context; authorized(req,db,scope='roles:read',permission='ACCESS_MANAGE'); require_read_attribute(req,'permissions'); return source.get('permissions')
GQL.type_map['User'].fields['permissions'].resolve=gql_permissions
def graphql_query_metrics(query):
    """Return maximum selection depth and expanded field count for one document."""
    try: document=graphql_parse(query)
    except Exception as exc: raise HTTPException(400,'Invalid GraphQL document') from exc
    fragments={node.name.value:node for node in document.definitions if getattr(node,'kind','')=='fragment_definition'}
    max_depth=0; field_count=0
    def walk(selection_set,depth,fragment_stack):
        nonlocal max_depth,field_count
        if not selection_set: return
        max_depth=max(max_depth,depth)
        for selection in selection_set.selections:
            if selection.kind=='field':
                field_count+=1; walk(selection.selection_set,depth+1,fragment_stack)
            elif selection.kind=='inline_fragment': walk(selection.selection_set,depth+1,fragment_stack)
            elif selection.kind=='fragment_spread':
                name=selection.name.value
                if name in fragment_stack: raise HTTPException(400,'Cyclic GraphQL fragments are not allowed')
                fragment=fragments.get(name)
                if fragment: walk(fragment.selection_set,depth+1,fragment_stack|{name})
    for operation in (node for node in document.definitions if getattr(node,'kind','')=='operation_definition'):
        walk(operation.selection_set,1,set())
    return max_depth,field_count
@app.post('/graphql')
async def graphql(req:Request):
    data=await req.json(); query=data.get('query','')
    if not isinstance(query,str) or not query.strip() or len(query)>20000: raise HTTPException(400,'Query exceeds lab complexity limit')
    depth,field_count=graphql_query_metrics(query)
    if depth>12 or field_count>200: raise HTTPException(400,'Query exceeds lab complexity limit')
    with Session.begin() as db:
        gate(db,'graphql'); authorized(req,db)
        result=graphql_sync(GQL,query,variable_values=data.get('variables'),operation_name=data.get('operationName'),context_value=(req,db)); out={'data':result.data}
        if result.errors:
            out['errors']=[{'message':e.message,'path':e.path} for e in result.errors]; db.rollback()
        return out

SOAP11='http://schemas.xmlsoap.org/soap/envelope/'
SOAP12='http://www.w3.org/2003/05/soap-envelope'
NS='urn:identity-api-lab'
def soap_response(ns,op,data=None,error=None):
    envelope=Element('{'+ns+'}Envelope'); envelope.set('xmlns:env',ns); body=SubElement(envelope,'{'+ns+'}Body')
    def append(parent,key,value):
        el=SubElement(parent,'{'+NS+'}'+key)
        if isinstance(value,dict):
            for k,v in value.items(): append(el,k,v)
        elif isinstance(value,list):
            for v in value: append(el,'item',v)
        elif isinstance(value,bool): el.text=str(value).lower()
        else: el.text=str(value) if value is not None else ''
    if error:
        fault=SubElement(body,'{'+ns+'}Fault')
        if ns==SOAP11: SubElement(fault,'faultcode').text='env:Client'; SubElement(fault,'faultstring').text=error
        else:
            SubElement(SubElement(fault,'{'+ns+'}Code'),'{'+ns+'}Value').text='env:Sender'
            textnode=SubElement(SubElement(fault,'{'+ns+'}Reason'),'{'+ns+'}Text'); textnode.set('{http://www.w3.org/XML/1998/namespace}lang','en'); textnode.text=error
    else: append(body,op+'Response',data)
    return Response(tostring(envelope,encoding='utf-8',xml_declaration=True),status_code=500 if error else 200,media_type='application/soap+xml' if ns==SOAP12 else 'text/xml')
@app.get('/soap')
def wsdl(req:Request):
    if 'wsdl' not in req.query_params: return {'documentation':'Append ?wsdl to retrieve WSDL 1.1'}
    location=str(req.base_url).rstrip('/')+'/soap'
    operations=['GetUser','ListUsers','CreateUser','UpdateUser','DisableUser','EnableUser','DeleteUser']
    elements=''.join('<xsd:element name="'+op+'"><xsd:complexType><xsd:sequence>'+''.join('<xsd:element name="'+field+'" type="xsd:string" minOccurs="0"/>' for field in ['userId','userName','displayName','email','password','active'])+'</xsd:sequence></xsd:complexType></xsd:element><xsd:element name="'+op+'Response"><xsd:complexType><xsd:sequence><xsd:any minOccurs="0" maxOccurs="unbounded" processContents="lax"/></xsd:sequence></xsd:complexType></xsd:element>' for op in operations)
    messages=''.join('<message name="'+op+'Request"><part name="parameters" element="tns:'+op+'"/></message><message name="'+op+'Response"><part name="parameters" element="tns:'+op+'Response"/></message>' for op in operations)
    port='<portType name="IdentityPortType">'+''.join('<operation name="'+op+'"><input message="tns:'+op+'Request"/><output message="tns:'+op+'Response"/></operation>' for op in operations)+'</portType>'
    bindings=''
    for prefix,name in [('soap','Soap11'),('soap12','Soap12')]:
        bindings+='<binding name="'+name+'Binding" type="tns:IdentityPortType"><'+prefix+':binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>'+''.join('<operation name="'+op+'"><'+prefix+':operation soapAction="urn:identity-api-lab/'+op+'"/><input><'+prefix+':body use="literal"/></input><output><'+prefix+':body use="literal"/></output></operation>' for op in operations)+'</binding>'
    service='<service name="IdentityService">'+''.join('<port name="'+n+'Port" binding="tns:'+n+'Binding"><'+p+':address location="'+location+'"/></port>' for p,n in [('soap','Soap11'),('soap12','Soap12')])+'</service>'
    return Response('<?xml version="1.0"?><definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="'+NS+'" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/" targetNamespace="'+NS+'"><types><xsd:schema targetNamespace="'+NS+'" elementFormDefault="qualified">'+elements+'</xsd:schema></types>'+messages+port+bindings+service+'</definitions>',media_type='text/xml')
@app.post('/soap')
async def soap(req:Request):
    ns=SOAP11
    try:
        raw=await req.body()
        if len(raw)>100000: raise HTTPException(413,'Envelope too large')
        root=fromstring(raw); ns=root.tag.split('}')[0].lstrip('{')
        if ns not in (SOAP11,SOAP12) or root.tag!='{'+ns+'}Envelope': raise HTTPException(400,'Invalid SOAP envelope')
        body=root.find('{'+ns+'}Body')
        if body is None or len(body)!=1: raise HTTPException(400,'One SOAP operation is required')
        operation=body[0]; op=operation.tag.split('}')[-1]; data={el.tag.split('}')[-1]:el.text or '' for el in operation}; id=data.get('userId')
        if operation.tag!='{'+NS+'}'+op: raise HTTPException(400,'Unknown operation namespace')
        with Session.begin() as db:
            gate(db,'soap12' if ns==SOAP12 else 'soap11'); write=op not in ('GetUser','ListUsers'); authorized(req,db,scope='users:write' if write else 'users:read',permission='USER_UPDATE' if write else 'CUSTOMER_READ')
            if op=='GetUser': result=api_user(req,db,required(db,'user',id))
            elif op=='ListUsers': result={'users':[api_user(req,db,u) for u in rows(db,'user') if not u['deleted']]}
            elif op=='CreateUser':
                authorized(req,db,scope='users:write',permission='USER_CREATE'); payload=scim_input(data)
                if 'active' in payload: payload['active']=str(payload['active']).lower()=='true'
                created=create_user(db,req,payload); result=api_user(req,db,required(db,'user',created['id']))
            elif op=='UpdateUser':
                payload=scim_input(data)
                if 'active' in payload: authorized(req,db,scope='users:write',permission='USER_STATUS_MANAGE'); payload['active']=str(payload['active']).lower()=='true'
                update_user(db,req,id,payload); result=api_user(req,db,required(db,'user',id))
            elif op in ('DisableUser','EnableUser','DeleteUser'):
                authorized(req,db,scope='users:write',permission='USER_STATUS_MANAGE'); update_user(db,req,id,{'active':op=='EnableUser',**({'deleted':True} if op=='DeleteUser' else {})}); result=api_user(req,db,required(db,'user',id))
            else: raise HTTPException(400,'Unknown SOAP operation')
            return soap_response(ns,op,result)
    except HTTPException as e:
        response=soap_response(ns if ns in (SOAP11,SOAP12) else SOAP11,'',error=str(e.detail))
        if e.status_code in (401,403,503): response.status_code=e.status_code
        return response
    except Exception: return soap_response(SOAP11,'',error='Malformed XML envelope')

@app.get('/banking/dashboard')
def bank_dashboard(req:Request):
    with Session() as db:
        u=authorized(req,db); perms=u['permissions']
        accounts=rows(db,'account') if 'ACCOUNT_READ' in perms else []; payments=rows(db,'payment') if set(perms).intersection({'TRANSACTION_READ','TRANSACTION_CREATE','TRANSACTION_APPROVE'}) else []; transactions=rows(db,'transaction') if 'TRANSACTION_READ' in perms else []
        return {'user':u,'permissions':perms,'customers':len(rows(db,'customer')) if 'CUSTOMER_READ' in perms else 0,'accounts':len(accounts),'totalBalance':str(sum((Decimal(a['balance']) for a in accounts),Decimal('0.00'))) if accounts else None,'currency':'USD','pendingPayments':sum(p['status']=='Pending' for p in payments) if 'TRANSACTION_APPROVE' in perms else 0,'myApprovals':sum(p['status']=='Pending' and p.get('assignedApproverId')==u['id'] for p in payments) if 'TRANSACTION_APPROVE' in perms else 0,'recentPayments':sorted(payments,key=lambda x:x.get('createdAt',''),reverse=True)[:5],'recentTransactions':sorted(transactions,key=lambda x:x.get('completedAt',x.get('approvedAt','')),reverse=True)[:5]}
@app.get('/banking/{collection}')
def bank_list(collection:str,req:Request):
    resources={'customers':('customer','CUSTOMER_READ'),'accounts':('account','ACCOUNT_READ'),'transactions':('transaction','TRANSACTION_READ'),'payments':('payment','TRANSACTION_READ')}
    if collection not in resources: raise HTTPException(404,'Unknown collection')
    kind,permission=resources[collection]
    with Session() as db:
        authorized(req,db,scope='banking:read',permission=permission); return rows(db,kind)
@app.post('/banking/payments',status_code=201)
async def payment_create(req:Request):
    data=await req.json()
    try: amount=Decimal(str(data.get('amount')))
    except InvalidOperation: raise HTTPException(400,'Invalid amount')
    if not amount.is_finite() or amount<=0 or amount>Decimal('1000000') or amount!=amount.quantize(Decimal('.01')): raise HTTPException(400,'Amount must be 0.01–1,000,000 with two decimals')
    with Session.begin() as db:
        actor=authorized(req,db,scope='banking:write',permission='TRANSACTION_CREATE'); source=required(db,'account',data.get('fromAccountId')); dest=required(db,'account',data.get('toAccountId'))
        if source['id']==dest['id']: raise HTTPException(400,'Choose different accounts')
        if source.get('status')!='Active' or dest.get('status')!='Active': raise HTTPException(409,'Both accounts must be active')
        if source.get('currency')!=dest.get('currency'): raise HTTPException(409,'Cross-currency payments are not enabled in this lab')
        candidates=[u for u in rows(db,'user') if u['id']!=actor['id'] and u['active'] and not u['locked'] and not u['deleted'] and 'TRANSACTION_APPROVE' in effective(db,u)]
        if not candidates: raise HTTPException(409,'No eligible approver is available')
        pending=rows(db,'payment'); preferred={'Treasury','Risk & Compliance'} if amount>=Decimal('10000') else {'Risk & Compliance','Retail Banking'}
        candidates.sort(key=lambda u:(u.get('department') not in preferred,sum(p.get('status')=='Pending' and p.get('assignedApproverId')==u['id'] for p in pending),u['displayName']))
        approver=candidates[0]; stamp=now(); tier='Enhanced review' if amount>=Decimal('10000') else 'Standard review'
        p=dict(id=uid(),fromAccountId=source['id'],fromAccountNumber=source.get('number'),fromCustomer=source.get('customerName'),toAccountId=dest['id'],toAccountNumber=dest.get('number'),toCustomer=dest.get('customerName'),amount=str(amount),currency=source.get('currency','USD'),reference=str(data.get('reference','Synthetic payment'))[:200],status='Pending',approvalTier=tier,createdBy=actor['id'],createdByName=actor.get('displayName',actor.get('username')),assignedApproverId=approver['id'],assignedApproverName=approver['displayName'],createdAt=stamp,approvalHistory=[{'action':'Submitted','actor':actor.get('displayName',actor.get('username')),'timestamp':stamp},{'action':'Assigned','actor':'Workflow engine','detail':approver['displayName'],'timestamp':stamp}]); save(db,'payment',p); audit(db,req,'payment.create',p['id'],{'amount':str(amount),'assignedApproverId':approver['id'],'approvalTier':tier}); emit_webhooks(db,'payment.created',p); return p
@app.post('/banking/payments/{id}/approve')
def payment_approve(id:str,req:Request):
    with Session.begin() as db:
        actor=authorized(req,db,scope='banking:write',permission='TRANSACTION_APPROVE')
        # Lock payment and accounts where supported to prevent duplicate approvals or lost balances.
        db.scalar(select(Record).where(Record.key=='payment:'+id).with_for_update())
        p=required(db,'payment',id)
        if actor['id']==p['createdBy']: raise HTTPException(403,'Maker cannot approve their own payment')
        if p.get('assignedApproverId') and actor['id']!=p['assignedApproverId']: raise HTTPException(403,'This payment is assigned to another approver')
        if p['status']!='Pending': raise HTTPException(409,'Payment already processed')
        for aid in sorted([p['fromAccountId'],p['toAccountId']]): db.scalar(select(Record).where(Record.key=='account:'+aid).with_for_update())
        source=required(db,'account',p['fromAccountId']); dest=required(db,'account',p['toAccountId']); amount=Decimal(p['amount'])
        if Decimal(source['balance'])<amount: raise HTTPException(409,'Insufficient synthetic balance')
        source['balance']=str(Decimal(source['balance'])-amount); dest['balance']=str(Decimal(dest['balance'])+amount); save(db,'account',source); save(db,'account',dest)
        stamp=now(); transaction_id=uid(); history=p.get('approvalHistory',[])+[{'action':'Approved','actor':actor.get('displayName',actor.get('username')),'timestamp':stamp},{'action':'Posted','actor':'Core ledger simulator','detail':transaction_id,'timestamp':stamp}]
        p.update(status='Approved',approvedBy=actor['id'],approvedByName=actor.get('displayName',actor.get('username')),approvedAt=stamp,completedAt=stamp,transactionId=transaction_id,approvalHistory=history); save(db,'payment',p); save(db,'transaction',{**p,'id':transaction_id,'paymentId':p['id'],'status':'Completed'}); audit(db,req,'payment.approve',id,{'transactionId':transaction_id,'amount':p['amount']}); emit_webhooks(db,'payment.approved',p); return p
@app.post('/banking/payments/{id}/reject')
async def payment_reject(id:str,req:Request):
    data=await req.json(); reason=str(data.get('reason','')).strip()
    if len(reason)<3 or len(reason)>300: raise HTTPException(400,'A rejection reason of 3–300 characters is required')
    with Session.begin() as db:
        actor=authorized(req,db,scope='banking:write',permission='TRANSACTION_APPROVE'); db.scalar(select(Record).where(Record.key=='payment:'+id).with_for_update()); payment=required(db,'payment',id)
        if actor['id']==payment['createdBy']: raise HTTPException(403,'Maker cannot decide their own payment')
        if payment.get('assignedApproverId') and actor['id']!=payment['assignedApproverId']: raise HTTPException(403,'This payment is assigned to another approver')
        if payment['status']!='Pending': raise HTTPException(409,'Payment already processed')
        stamp=now(); payment.update(status='Rejected',rejectedBy=actor['id'],rejectedByName=actor.get('displayName',actor.get('username')),rejectedAt=stamp,decisionReason=reason,approvalHistory=payment.get('approvalHistory',[])+[{'action':'Rejected','actor':actor.get('displayName',actor.get('username')),'detail':reason,'timestamp':stamp}]); save(db,'payment',payment); audit(db,req,'payment.reject',id,{'reason':reason}); emit_webhooks(db,'payment.rejected',payment); return payment

dist=Path(os.getenv('FRONTEND_DIST',str(Path(__file__).resolve().parent.parent/'frontend'/'dist')))
if (dist/'assets').exists(): app.mount('/assets',StaticFiles(directory=dist/'assets'),name='assets')
@app.get('/{path:path}',include_in_schema=False)
def frontend(path:str):
    if path.startswith(('api/','admin-api/','scim/','oauth/','banking/','auth/')): raise HTTPException(404,'Route not found')
    if (dist/'index.html').exists(): return FileResponse(dist/'index.html')
    return {'application':'Identity API Lab','status':'Backend ready; build frontend to load UI','docs':'/docs'}
