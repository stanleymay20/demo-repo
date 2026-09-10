import re, time, hashlib, gc, json, os
import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, Comment
from datasets import load_dataset
from sentence_transformers import SentenceTransformer
import torch
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (confusion_matrix, precision_score, recall_score, f1_score,
    balanced_accuracy_score, roc_auc_score, roc_curve, precision_recall_curve)

SEED=42
os.environ['TOKENIZERS_PARALLELISM']='false'
torch.set_num_threads(2)
lab={'no':0,'yes':1}
ws=re.compile(r'\s+')

def dig(s,n=32768):
    s='' if s is None else str(s); a=hashlib.sha256(); b=hashlib.sha256(); first=True; space=False
    for i in range(0,len(s),n):
        c=s[i:i+n]; a.update(c.encode('utf8','ignore')); z=ws.sub(' ',c.lower())
        lead=z.startswith(' '); tail=z.endswith(' '); core=z.strip()
        if core:
            if not first and (space or lead): b.update(b' ')
            b.update(core.encode('utf8','ignore')); first=False
        space=tail or (space and not core)
    return a.digest(),b.digest()

def audit(d):
    raw=set(); norm=set(); exact=normdup=miss=0
    for B in d.iter(batch_size=16):
        for s in B['content']:
            miss += s is None; a,b=dig(s); exact += a in raw; normdup += b in norm
            raw.add(a); norm.add(b)
    return miss,exact,normdup,norm

P={'comments':r'<!--','display_none':r'display\s*:\s*none','visibility_hidden':r'visibility\s*:\s*hidden',
   'hidden_input':r'<input[^>]+type\s*=\s*[\'\"]?hidden','data_attr':r'\sdata-[\w-]+\s*=','script':r'<script\b','style':r'<style\b'}
A={'aria-label','title','alt','value','style','hidden','placeholder','onclick'}

def views(raw):
    raw=str(raw); s=BeautifulSoup(raw,'lxml'); com=[str(x) for x in s.find_all(string=lambda t:isinstance(t,Comment))]
    hid=[]; att=[]
    for tag in s.find_all(True):
        st=str(tag.get('style','')).lower().replace(' ','')
        if tag.has_attr('hidden') or 'display:none' in st or 'visibility:hidden' in st or (tag.name=='input' and str(tag.get('type','')).lower()=='hidden'):
            hid.append(tag.get_text(' ',strip=True))
        for k,v in tag.attrs.items():
            if k.startswith('data-') or k in A:
                att.append(f"{k} {' '.join(map(str,v)) if isinstance(v,list) else v}")
    for tag in s(['script','style']): tag.decompose()
    return ' '.join(s.stripped_strings),' '.join(com+hid+att)

def enrich(d,ids):
    R=[]
    for B in d.select([int(i) for i in ids]).iter(batch_size=16):
        for raw,L in zip(B['content'],B['label']):
            v,h=views(raw)
            R.append({'visible':v,'hidden':h,'y':lab[L],'raw_len':len(raw),'hidden_len':len(h),'visible_ratio':len(v)/max(len(raw),1)})
    return pd.DataFrame(R)

def met(y,p,t):
    z=(p>=t).astype(int); tn,fp,fn,tp=confusion_matrix(y,z).ravel()
    return dict(threshold=float(t),precision=float(precision_score(y,z,zero_division=0)),recall=float(recall_score(y,z,zero_division=0)),
                f1=float(f1_score(y,z,zero_division=0)),balanced_acc=float(balanced_accuracy_score(y,z)),roc_auc=float(roc_auc_score(y,p)),
                fpr=float(fp/(fp+tn)),tn=int(tn),fp=int(fp),fn=int(fn),tp=int(tp))

def th_fpr(y,p):
    f,t,h=roc_curve(y,p); q=np.where(f<=.01)[0]; return float(h[q[np.argmax(t[q])]])

def th_f1(y,p):
    a,b,h=precision_recall_curve(y,p); f=2*a[:-1]*b[:-1]/(a[:-1]+b[:-1]+1e-12); return float(h[np.argmax(f)])

def summarize(y,p):
    ts,tf=th_fpr(y,p),th_f1(y,p)
    return {'security':met(y,p,ts),'f1_opt':met(y,p,tf)}

def contextual(enc,df,K=6,W=180):
    texts=[]; counts=[]
    for r in df.itertuples():
        z=(str(r.hidden)+' '+str(r.visible)).split()
        if not z: z=['']
        n=min(K,max(1,int(np.ceil(len(z)/W))))
        starts=np.linspace(0,max(0,len(z)-W),n,dtype=int)
        q=[' '.join(z[s:s+W]) for s in starts]
        texts.extend(q); counts.append(len(q))
    E=enc.encode(texts,batch_size=64,show_progress_bar=True,convert_to_numpy=True,normalize_embeddings=True)
    out=[]; p=0
    for n in counts:
        q=E[p:p+n]; out.append(np.r_[q.mean(0),q.max(0)]); p+=n
    return np.asarray(out,dtype=np.float32)

print('Loading BrowseSafe-Bench...')
ds=load_dataset('perplexity-ai/browsesafe-bench')
tr,te=ds['train'],ds['test']

tm,td,tnd,tn=audit(te); raw=set(); seen=set(); keep=[]; train_miss=train_exact=train_ndup=overlap=0; i=0
for B in tr.iter(batch_size=16):
    for s in B['content']:
        train_miss += s is None; a,b=dig(s); train_exact += a in raw; raw.add(a)
        if b in seen: train_ndup += 1
        elif b in tn: overlap += 1
        else: seen.add(b); keep.append(i)
        i += 1
print('Integrity', train_miss,tm,train_exact,td,train_ndup,tnd,overlap)
tr=tr.select(keep); y=np.array([lab[x] for x in tr['label']],dtype=np.int8)
idx=np.arange(len(tr)); work,ih=train_test_split(idx,test_size=.15,stratify=y,random_state=SEED)
idv,iv=train_test_split(work,test_size=.1764706,stratify=y[work],random_state=SEED)
del raw,seen,tn,keep,idx,ds; gc.collect()
print('Splits',len(idv),len(iv),len(ih),len(te))

print('Extracting views...')
t=time.time(); X,Y,H=enrich(tr,idv),enrich(tr,iv),enrich(tr,ih); extract_s=time.time()-t
print('View extraction seconds',extract_s)
yt,yv=X.y,Y.y

m1=Pipeline([('v',TfidfVectorizer(ngram_range=(1,2),min_df=2,max_df=.98,max_features=22000,sublinear_tf=True,dtype=np.float32)),
             ('c',LogisticRegression(max_iter=1000,random_state=SEED))])
t=time.time(); m1.fit(X.visible,yt); m1_fit=time.time()-t
pv=m1.predict_proba(Y.visible)[:,1]; m1_val=summarize(yv,pv)
ph=m1.predict_proba(H.visible)[:,1]; m1_hold={'security':met(H.y,ph,m1_val['security']['threshold']), 'f1_opt':met(H.y,ph,m1_val['f1_opt']['threshold'])}
print('M1 validation',m1_val)
print('M1 audit',m1_hold)

print('Loading MiniLM...')
enc=SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2',device='cpu')
enc.max_seq_length=256
print('Embedding development/validation/audit...')
t=time.time(); CX=contextual(enc,X); CY=contextual(enc,Y); CH=contextual(enc,H); emb_s=time.time()-t
m4=LogisticRegression(max_iter=1000,random_state=SEED)
t=time.time(); m4.fit(CX,yt); m4_fit=time.time()-t
pv4=m4.predict_proba(CY)[:,1]; m4_val=summarize(yv,pv4)
ph4=m4.predict_proba(CH)[:,1]; m4_hold={'security':met(H.y,ph4,m4_val['security']['threshold']), 'f1_opt':met(H.y,ph4,m4_val['f1_opt']['threshold'])}
params=int(sum(p.numel() for p in enc.parameters())+m4.coef_.size+1)
print('M4 validation',m4_val)
print('M4 audit',m4_hold)

result={
 'integrity':{'train_missing':train_miss,'test_missing':tm,'train_exact_duplicates':train_exact,'test_exact_duplicates':td,'train_norm_duplicates':train_ndup,'test_norm_duplicates':tnd,'train_test_overlap':overlap},
 'splits':{'development':len(idv),'validation':len(iv),'audit':len(ih),'test':len(te)},
 'timing':{'view_extraction_s':extract_s,'m1_fit_s':m1_fit,'m4_embedding_s':emb_s,'m4_fit_s':m4_fit},
 'm1':{'validation':m1_val,'audit':m1_hold,'params':int(m1.named_steps['c'].coef_.size+1)},
 'm4':{'validation':m4_val,'audit':m4_hold,'params':params},
 'selected':'M4 MiniLM context' if (m4_val['security']['recall']>m1_val['security']['recall'] and m4_hold['security']['recall']>m1_hold['security']['recall']) else 'M1 Visible LR'
}
with open('agentshield_results.json','w') as f: json.dump(result,f,indent=2)
print(json.dumps(result,indent=2))
