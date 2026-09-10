# Auto-extracted runtime QA from AgentShield v13.5

import re,time,hashlib,gc,warnings,numpy as np,pandas as pd,matplotlib.pyplot as plt,torch
from IPython.display import Markdown, display
from bs4 import BeautifulSoup,Comment
from datasets import load_dataset
from sentence_transformers import SentenceTransformer
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression,SGDClassifier
from sklearn.dummy import DummyClassifier
from sklearn.metrics import (confusion_matrix,precision_score,recall_score,f1_score,
 balanced_accuracy_score,roc_auc_score,roc_curve,precision_recall_curve,ConfusionMatrixDisplay)
warnings.filterwarnings("ignore"); SEED=42
def clean(ax):
    ax.grid(False); ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)

ds=load_dataset("perplexity-ai/browsesafe-bench",token=False)
tr,te=ds["train"],ds["test"]; lab={"no":0,"yes":1}; ws=re.compile(r"\s+")
def dig(s,n=32768):
    s="" if s is None else str(s); a=hashlib.sha256(); b=hashlib.sha256(); first=True; space=False
    for i in range(0,len(s),n):
        c=s[i:i+n]; a.update(c.encode("utf8","ignore")); z=ws.sub(" ",c.lower())
        lead=z.startswith(" "); tail=z.endswith(" "); core=z.strip()
        if core:
            if not first and (space or lead): b.update(b" ")
            b.update(core.encode("utf8","ignore")); first=False
        space=tail or (space and not core)
    return a.digest(),b.digest()
def audit(d):
    raw=set(); norm=set(); exact=normdup=miss=0
    for B in d.iter(batch_size=16):
        for s in B["content"]:
            miss+=s is None; a,b=dig(s); exact+=a in raw; normdup+=b in norm
            raw.add(a); norm.add(b)
    return miss,exact,normdup,norm

tm,td,tnd,tn=audit(te); raw=set(); seen=set(); keep=[]
train_miss=train_exact=train_ndup=overlap=0; i=0
for B in tr.iter(batch_size=16):
    for s in B["content"]:
        train_miss+=s is None; a,b=dig(s); train_exact+=a in raw; raw.add(a)
        if b in seen: train_ndup+=1
        elif b in tn: overlap+=1
        else: seen.add(b); keep.append(i)
        i+=1
print("Missing train/test:",train_miss,tm)
print("Exact duplicates train/test:",train_exact,td,"| normalized duplicates:",train_ndup,tnd)
print("Normalized train-test overlap:",overlap,"| training rows removed:",len(tr)-len(keep))

tr=tr.select(keep); y=np.array([lab[x] for x in tr["label"]],dtype=np.int8)
idx=np.arange(len(tr)); work,ih=train_test_split(idx,test_size=.15,stratify=y,random_state=SEED)
idv,iv=train_test_split(work,test_size=.1764706,stratify=y[work],random_state=SEED)
del raw,seen,tn,keep,idx,ds; gc.collect()
print("Development / validation / audit / test:",len(idv),len(iv),len(ih),len(te))

P={"comments":r"<!--","display_none":r"display\s*:\s*none","visibility_hidden":r"visibility\s*:\s*hidden",
"hidden_input":r"<input[^>]+type\s*=\s*['\"]?hidden","data_attr":r"\sdata-[\w-]+\s*=","script":r"<script\b","style":r"<style\b"}
A={"aria-label","title","alt","value","style","hidden","placeholder","onclick"}
def views(raw):
    raw=str(raw); s=BeautifulSoup(raw,"lxml"); com=[str(x) for x in s.find_all(string=lambda t:isinstance(t,Comment))]
    hid=[]; att=[]
    for tag in s.find_all(True):
        st=str(tag.get("style","")).lower().replace(" ","")
        if tag.has_attr("hidden") or "display:none" in st or "visibility:hidden" in st or (tag.name=="input" and str(tag.get("type","")).lower()=="hidden"):
            hid.append(tag.get_text(" ",strip=True))
        for k,v in tag.attrs.items():
            if k.startswith("data-") or k in A: att.append(f"{k} {' '.join(map(str,v)) if isinstance(v,list) else v}")
    for tag in s(["script","style"]): tag.decompose()
    return " ".join(s.stripped_strings)," ".join(com+hid+att)
def enrich(d,ids):
    R=[]
    for B in d.select([int(i) for i in ids]).iter(batch_size=16):
        for raw,L in zip(B["content"],B["label"]):
            v,h=views(raw); q={"text":v,"hidden":h,"y":lab[L],"raw_len":len(raw),"hidden_len":len(h)}
            q["text_ratio"]=len(v)/max(len(raw),1)
            for k,p in P.items(): q[k]=len(re.findall(p,raw,flags=re.I))
            R.append(q)
    return pd.DataFrame(R)

t=time.time(); X,Y=enrich(tr,idv),enrich(tr,iv); extract_ms=1000*(time.time()-t)/(len(X)+len(Y))
bal=np.bincount(y,minlength=2)/len(y)*100
print(f"Class balance: {bal[0]:.1f}% benign / {bal[1]:.1f}% injection")
print(f"HTML representation extraction: {extract_ms:.2f} ms/page")

lb=np.log10(X.loc[X.y==0,"raw_len"].clip(lower=1)); li=np.log10(X.loc[X.y==1,"raw_len"].clip(lower=1))
ratio=10**abs(np.median(li)-np.median(lb))
print("Median page length ratio:",round(float(ratio),4))
g=pd.Series({k:(X.loc[X.y==1,k]>0).mean()-(X.loc[X.y==0,k]>0).mean() for k in P}).sort_values()
print("Largest structural class gap percentage points:",round(float(100*g.abs().max()),4))

def met(y,p,t):
    z=(p>=t).astype(int); tn,fp,fn,tp=confusion_matrix(y,z).ravel()
    return dict(threshold=float(t),precision=precision_score(y,z,zero_division=0),recall=recall_score(y,z,zero_division=0),
        f1=f1_score(y,z,zero_division=0),balanced_acc=balanced_accuracy_score(y,z),roc_auc=roc_auc_score(y,p),
        fpr=fp/(fp+tn),tn=int(tn),fp=int(fp),fn=int(fn),tp=int(tp))
def th_fpr(y,p):
    f,t,h=roc_curve(y,p); q=np.where(f<=.01)[0]; return h[q[np.argmax(t[q])]]
def th_f1(y,p):
    a,b,h=precision_recall_curve(y,p); f=2*a[:-1]*b[:-1]/(a[:-1]+b[:-1]+1e-12); return h[np.argmax(f)]
def summ(n,y,p,secs):
    a,b=th_fpr(y,p),th_f1(y,p); s,f=met(y,p,a),met(y,p,b)
    return dict(model=n,sec_threshold=a,recall_at_1pct_fpr=s["recall"],sec_fpr=s["fpr"],roc_auc=s["roc_auc"],
        best_val_f1=f["f1"],f1_threshold=b,fit_s=secs)
def wilson(k,n,z=1.96):
    p=k/n; d=1+z*z/n; c=(p+z*z/(2*n))/d; h=z*np.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return c-h,c+h

S=list(P)+["raw_len","hidden_len","text_ratio"]; yt,yv=X.y,Y.y; rows=[]; objs={}
def add(n,p,secs,params,ms):
    r=summ(n,yv,p,secs); r.update(params=params,ms_page=ms); rows.append(r)

d=DummyClassifier(strategy="prior").fit(np.zeros((len(yt),1)),yt); p0=d.predict_proba(np.zeros((len(yv),1)))[:,1]
add("M0 Dummy",p0,0,1,0)

m1=Pipeline([("v",TfidfVectorizer(ngram_range=(1,2),min_df=2,max_df=.98,max_features=22000,sublinear_tf=True,dtype=np.float32)),
             ("c",LogisticRegression(max_iter=1000,random_state=SEED))])
t=time.time(); m1.fit(X.text,yt); fit=time.time()-t
t=time.time(); p=m1.predict_proba(Y.text)[:,1]; ms=1000*(time.time()-t)/len(Y)
add("M1 Text LR",p,fit,m1.named_steps["c"].coef_.size+1,ms); objs["M1 Text LR"]=(m1,None)

pre2=ColumnTransformer([("v",TfidfVectorizer(analyzer="char",ngram_range=(3,5),min_df=3,max_features=30000,dtype=np.float32),"text"),
                        ("h",TfidfVectorizer(analyzer="char",ngram_range=(3,5),min_df=2,max_features=8000,dtype=np.float32),"hidden")])
t=time.time(); a=pre2.fit_transform(X); fitprep=time.time()-t
m2=SGDClassifier(loss="log_loss",alpha=3e-5,average=True,random_state=SEED)
t=time.time(); m2.fit(a,yt); fit=fitprep+time.time()-t
t=time.time(); b=pre2.transform(Y); p=m2.predict_proba(b)[:,1]; ms=1000*(time.time()-t)/len(Y)
add("M2 HTML-char",p,fit,m2.coef_.size+1,ms); objs["M2 HTML-char"]=(m2,pre2)
del a,b; gc.collect()

pre3=ColumnTransformer([("w",TfidfVectorizer(ngram_range=(1,2),min_df=2,max_features=16000,dtype=np.float32),"text"),
 ("v",TfidfVectorizer(analyzer="char",ngram_range=(3,5),min_df=3,max_features=24000,dtype=np.float32),"text"),
 ("h",TfidfVectorizer(analyzer="char",ngram_range=(3,5),min_df=2,max_features=6000,dtype=np.float32),"hidden"),
 ("s",StandardScaler(),S)])
t=time.time(); c=pre3.fit_transform(X); prepfit=time.time()-t
t=time.time(); e=pre3.transform(Y); predprep=time.time()-t
for al in [1e-5,3e-5,1e-4]:
    t=time.time(); clf=SGDClassifier(loss="log_loss",alpha=al,average=True,random_state=SEED).fit(c,yt); fit=prepfit+time.time()-t
    t=time.time(); p=clf.predict_proba(e)[:,1]; ms=1000*(predprep+time.time()-t)/len(Y)
    n=f"M3 Hybrid {al:g}"; add(n,p,fit,clf.coef_.size+1,ms); objs[n]=(clf,pre3)

R=pd.DataFrame(rows).set_index("model").sort_values(["recall_at_1pct_fpr","roc_auc","best_val_f1"],ascending=False)
print("VALIDATION RESULTS")
print(R.round(4).to_string())
win=R.index[0]
del c,e; gc.collect()

H=enrich(tr,ih); model,prep=objs[win]
ph=model.predict_proba(H.text)[:,1] if prep is None else model.predict_proba(prep.transform(H))[:,1]
sec,f1=met(H.y,ph,R.loc[win,"sec_threshold"]),met(H.y,ph,R.loc[win,"f1_threshold"])
print("AUDIT SECURITY",sec)
print("AUDIT F1",f1)
rci=wilson(sec["tp"],sec["tp"]+sec["fn"]); fci=wilson(sec["fp"],sec["fp"]+sec["tn"])
print("AUDIT 95% CI recall",rci,"FPR",fci)

enc=SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2",
 device="cuda" if torch.cuda.is_available() else "cpu"); enc.max_seq_length=256
def ctx(df,K=6,W=180):
    texts=[]; n=[]
    for r in df.itertuples():
        z=(str(r.hidden)+" "+str(r.text)).split() or [""]
        k=min(K,max(1,int(np.ceil(len(z)/W))))
        q=[" ".join(z[s:s+W]) for s in np.linspace(0,max(0,len(z)-W),k,dtype=int)]
        texts+=q; n.append(k)
    E=enc.encode(texts,batch_size=64,normalize_embeddings=True,convert_to_numpy=True)
    out=[]; p=0
    for k in n:
        q=E[p:p+k]; out.append(np.r_[q.mean(0),q.max(0)]); p+=k
    return np.asarray(out,np.float32)

t=time.time(); CX,CY,CH=ctx(X),ctx(Y),ctx(H); m4_encode_s=time.time()-t
m4=LogisticRegression(max_iter=1000,random_state=SEED).fit(CX,yt)
p4,h4=m4.predict_proba(CY)[:,1],m4.predict_proba(CH)[:,1]
s4,f4=th_fpr(yv,p4),th_f1(yv,p4)
m4_params=sum(p.numel() for p in enc.parameters())+m4.coef_.size+1
print("M4 validation security",met(yv,p4,s4))
print("M4 validation F1",met(yv,p4,f4))
print("M4 audit security",met(H.y,h4,s4))
print("M4 audit F1",met(H.y,h4,f4))
print("M4 parameters",m4_params,"contextual encoding seconds",round(m4_encode_s,1))

T=enrich(te,np.arange(len(te)))
FINAL_MODEL=objs["M1 Text LR"][0]; SEC_T=0.6680312752723694; F1_T=0.35975080728530884
pt=FINAL_MODEL.predict_proba(T.text)[:,1]
test_sec,test_f1=met(T.y,pt,SEC_T),met(T.y,pt,F1_T)
print("BENCHMARK SECURITY",test_sec)
print("BENCHMARK F1",test_f1)

# Hard QA assertions: fail the workflow if the repaired runtime diverges materially.
assert win=="M1 Text LR", win
assert abs(test_sec["recall"]-0.2791)<0.002, test_sec
assert abs(test_sec["fpr"]-0.0092)<0.002, test_sec
assert test_sec["tp"]==509 and test_sec["fp"]==17, test_sec
print("AGENTSHIELD_V13_5_RUNTIME_QA=PASS")
