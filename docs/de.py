import os,re,json,hashlib,collections
ROOT='/var/tmp/ng-sink/extracted-full'
MARK=re.compile(rb'trufflehog|Sha1-Hulud|Shai-Hulud|bun_environment|169\.254\.169\.254|metadata\.google\.internal|discord\.com/api/webhooks|api\.telegram\.org|webhook\.site|CreateCommitOnBranch|_authToken')
DOCEXT={'.md','.markdown','.txt','.rst','.html','.htm','.map','.yml','.yaml'}
DOCNAME={'LICENSE','NOTICE','CHANGELOG','README'}
ver_sigs={}; file_vers=collections.defaultdict(set); nver=0
for v in sorted(os.listdir(ROOT)):
    vp=os.path.join(ROOT,v); nver+=1
    # analysis root = the package/ dir, never above it
    proots=[]
    for dp,dn,fn in os.walk(vp):
        if os.path.basename(dp)=='package': proots.append(dp)
    hits=set()
    for pr in proots:
        for dp,dn,fn in os.walk(pr):
            if 'node_modules' in dp.split(os.sep): continue
            for f in fn:
                ext=os.path.splitext(f)[1].lower()
                if ext in DOCEXT or os.path.splitext(f)[0].upper() in DOCNAME: continue
                fp=os.path.join(dp,f)
                try:
                    if os.path.getsize(fp)>60_000_000: continue
                    b=open(fp,'rb').read()
                except Exception: continue
                if MARK.search(b):
                    h=hashlib.sha256(b).hexdigest()
                    hits.add(h); file_vers[h].add(v)
    if hits: ver_sigs[v]=frozenset(hits)
sigs=collections.Counter(ver_sigs.values())
print("versions total                :",nver)
print("versions with >=1 marker file :",len(ver_sigs))
print("distinct marker FILE contents :",len(file_vers))
print("distinct version SIGNATURES   :",len(sigs))
print("singleton signatures          :",sum(1 for s,c in sigs.items() if c==1))
mx=max(file_vers.items(),key=lambda kv:len(kv[1]))
print("largest single file spans     :",len(mx[1]),"versions  sha256",mx[0][:16])
print("largest signature covers      :",sigs.most_common(1)[0][1],"versions")
de=nver/len(sigs); print("DESIGN EFFECT 1443/sigs       : %.1f   sqrt=%.1f"%(de,de**0.5))
json.dump({"versions":nver,"marker_versions":len(ver_sigs),"distinct_files":len(file_vers),
           "distinct_signatures":len(sigs),"singletons":sum(1 for s,c in sigs.items() if c==1),
           "max_file_versions":len(mx[1]),"max_sig_versions":sigs.most_common(1)[0][1],
           "design_effect":round(de,1)}, open('/var/tmp/ng-sink/design-effect.json','w'), indent=1)
