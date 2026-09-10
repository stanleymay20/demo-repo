import re, time, hashlib, gc, json
import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, Comment
from datasets import load_dataset
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, balanced_accuracy_score, roc_auc_score

SEED=42
SECURITY_THRESHOLD=0.6680312752723694
F1_THRESHOLD=0.35975080728530884
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

def visible(raw):
    s=BeautifulSoup(str(raw),'lxml')
    for tag in s(['script','style']): tag.decompose()
    return ' '.join(s.stripped_strings)

def make_df(d,ids):
    rows=[]
    for B in d.select([int(i) for i in ids]).iter(batch_size=16):
        for raw,L in zip(B['content'],B['label']): rows.append({'visible':visible(raw),'y':lab[L]})
    return pd.DataFrame(rows)

def met(y,p,t):
    z=(p>=t).astype(int); tn,fp,fn,tp=confusion_matrix(y,z).ravel()
    return dict(threshold=float(t),precision=float(precision_score(y,z,zero_division=0)),recall=float(recall_score(y,z,zero_division=0)),
                f1=float(f1_score(y,z,zero_division=0)),balanced_acc=float(balanced_accuracy_score(y,z)),roc_auc=float(roc_auc_score(y,p)),
                fpr=float(fp/(fp+tn)),tn=int(tn),fp=int(fp),fn=int(fn),tp=int(tp))

def wilson(k,n,z=1.96):
    p=k/n; d=1+z*z/n; c=(p+z*z/(2*n))/d; h=z*np.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return [float(c-h),float(c+h)]

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
tr=tr.select(keep); y=np.array([lab[x] for x in tr['label']],dtype=np.int8)
idx=np.arange(len(tr)); work,ih=train_test_split(idx,test_size=.15,stratify=y,random_state=SEED)
idv,iv=train_test_split(work,test_size=.1764706,stratify=y[work],random_state=SEED)
print('Frozen split sizes',len(idv),len(iv),len(ih),len(te))

print('Building frozen M1 inputs...')
t=time.time(); X=make_df(tr,idv); T=make_df(te,np.arange(len(te))); prep_s=time.time()-t
m1=Pipeline([('v',TfidfVectorizer(ngram_range=(1,2),min_df=2,max_df=.98,max_features=22000,sublinear_tf=True,dtype=np.float32)),
             ('c',LogisticRegression(max_iter=1000,random_state=SEED))])
t=time.time(); m1.fit(X.visible,X.y); fit_s=time.time()-t
t=time.time(); pt=m1.predict_proba(T.visible)[:,1]; pred_s=time.time()-t
sec=met(T.y,pt,SECURITY_THRESHOLD); f1opt=met(T.y,pt,F1_THRESHOLD)
sec['recall_ci95']=wilson(sec['tp'],sec['tp']+sec['fn']); sec['fpr_ci95']=wilson(sec['fp'],sec['fp']+sec['tn'])
result={
 'frozen_model':'M1 Visible TF-IDF + Logistic Regression',
 'selection_basis':'Validation Recall@<=1% FPR; M4 rejected before official test',
 'security_threshold':SECURITY_THRESHOLD,
 'f1_threshold':F1_THRESHOLD,
 'integrity':{'train_missing':train_miss,'test_missing':tm,'train_exact_duplicates':train_exact,'test_exact_duplicates':td,'train_norm_duplicates':train_ndup,'test_norm_duplicates':tnd,'train_test_overlap':overlap},
 'split_sizes':{'development':len(idv),'validation':len(iv),'audit':len(ih),'official_test':len(te)},
 'timing':{'input_build_s':prep_s,'fit_s':fit_s,'predict_s':pred_s,'predict_ms_page':1000*pred_s/len(T)},
 'params':int(m1.named_steps['c'].coef_.size+1),
 'official_test':{'security':sec,'f1_threshold':f1opt}
}
with open('agentshield_final_test_results.json','w') as f: json.dump(result,f,indent=2)
print(json.dumps(result,indent=2))
