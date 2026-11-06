"""0003 T09: extract the RFC 7516 A.1/A.2 and RFC 7520 §5.1/§5.2 compact JWEs and RSA public keys.

Usage: python3 -I t09-extract-rfc-inputs.py <rfc7516.txt> <cookbook jwe dir> <out.json>
Historical: the T09 vector writer was not preserved; see conformance/README.md (Tools).
"""
import json, re, sys
rfc = open(sys.argv[1]).read()
cb = sys.argv[2]
def jwk_at(line_no):
    lines = rfc.split('\n')[line_no-1:]
    buf=''
    for l in lines:
        buf += l.strip()
        if l.strip().endswith('}'): break
    return json.loads(buf)
def compact_after(header):
    i = rfc.index(header)
    j = rfc.index('The final result in this example', i)
    seg = rfc[j:j+3000].split('is:',1)[1]
    toks=[]
    for l in seg.split('\n'):
        t=l.strip()
        if not t: 
            if toks: 
                if toks[-1].endswith('.') or len(''.join(toks).split('.'))<5: continue
                break
            continue
        if not re.fullmatch(r'[A-Za-z0-9_\-.]+', t):
            if toks and len(''.join(toks).split('.'))==5: break
            continue
        toks.append(t)
    return ''.join(toks)
out={}
a1=jwk_at(1806); a2=jwk_at(2086)
out['a1']={'key':{'kty':'RSA','n':a1['n'],'e':a1['e']},'compact':compact_after('A.1.7.  Complete Representation\n\n')}
out['a2']={'key':{'kty':'RSA','n':a2['n'],'e':a2['e']},'compact':compact_after('A.2.7.  Complete Representation\n\n')}
for k,f in [('c51','5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json'),('c52','5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json')]:
    d=json.load(open(cb+'/'+f)); key=d['input']['key']
    pub={x:key[x] for x in ['kty','kid','use','n','e'] if x in key}
    out[k]={'key':pub,'compact':d['output']['compact'],'alg':d['input']['alg'],'enc':d['input']['enc']}
for k,v in out.items():
    print(k, v['compact'][:60], len(v['compact'].split('.')), v['key'].get('kid'))
json.dump(out, open(sys.argv[3],'w'), indent=1)
