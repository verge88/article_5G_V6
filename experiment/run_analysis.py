#!/usr/bin/env python3
import argparse,csv,json,math,random,statistics,time,tracemalloc
from collections import Counter,defaultdict
from pathlib import Path
from sklearn.ensemble import IsolationForest

O=('S','E','D','P'); I={x:i for i,x in enumerate(O)}
def one(x):
 v=[0]*4; v[I[x]]=1; return tuple(v)
def add(a,b): return tuple(x+y for x,y in zip(a,b))
def vec(xs):
 c=Counter(xs); return tuple(c[x] for x in O)
def feasible(ds):
 V={(0,0,0,0)}
 for d in ds: V={add(v,one(x)) for v in V for x in d}
 return V
def exact(ds,r):
 V=feasible(ds); return ('NOT_REFUTED' if tuple(r) in V else 'REPORT_INCONSISTENT'),V
def hier(ds,r,z=3):
 chunks=[[] for _ in range(z)]
 for i,d in enumerate(ds): chunks[i%z].append(d)
 V={(0,0,0,0)}
 for c in chunks: V={add(a,b) for a in V for b in feasible(c)}
 return ('NOT_REFUTED' if tuple(r) in V else 'REPORT_INCONSISTENT'),V
def interval(ds,rs):
 lo=sum(d=={'S'} for d in ds); hi=sum('S' in d for d in ds)
 return 'NOT_REFUTED' if lo<=rs<=hi else 'REPORT_INCONSISTENT'
def naive(ds,rs): return 'NOT_REFUTED' if sum(d=={'S'} for d in ds)==rs else 'REPORT_INCONSISTENT'
def box(ds,r):
 mn=[sum(d=={x} for d in ds) for x in O]; mx=[sum(x in d for d in ds) for x in O]
 return 'NOT_REFUTED' if all(a<=x<=b for a,x,b in zip(mn,r,mx)) else 'REPORT_INCONSISTENT'
def domains(t,obs): return [{x} if y else set(O) for x,y in zip(t,obs)]

def truth(kind,n,rng):
 P={'normal':(.93,.05,.01,.01),'overload':(.58,.24,.02,.16),'mixed':(.64,.18,.10,.08),'inflate':(.82,.10,.03,.05),'hide':(.74,.18,.02,.06),'scope':(.72,.17,.03,.08),'replay':(.90,.07,.01,.02),'loss':(.88,.08,.01,.03),'epoch':(.86,.08,.02,.04),'collusion':(.76,.15,.03,.06),'witness_bad':(.70,.18,.04,.08)}[kind]
 out=[]
 for _ in range(n):
  q=rng.random(); a=0
  for x,p in zip(O,P):
   a+=p
   if q<=a: out.append(x); break
 return out
def mask(kind,n,rng):
 m={'normal':.03,'overload':.10,'mixed':.12,'inflate':.20,'hide':.20,'scope':.15,'replay':.04,'loss':.45,'epoch':.18,'collusion':.22,'witness_bad':.05}[kind]
 return [rng.random()>=m for _ in range(n)]
def report(t,kind):
 r=list(vec(t)); false=False; meta={}
 if kind=='inflate':
  d=max(1,min(3,sum(r[1:]) or 1)); r[0]+=d
  for j in (1,2,3): q=min(d,r[j]); r[j]-=q; d-=q
  false=True
 elif kind=='hide':
  d=max(1,min(3,r[1])) if r[1] else 1; r[1]=max(0,r[1]-d); r[0]+=d; false=True
 elif kind in ('scope','witness_bad'):
  n=sum(r); r=[n,0,0,0]; false=tuple(r)!=vec(t); meta['outside_trust_model']=kind=='witness_bad'
 elif kind=='collusion':
  d=max(1,min(2,sum(r[1:]) or 1)); r[0]+=d
  for j in (1,2,3): q=min(d,r[j]); r[j]-=q; d-=q
  false=True; meta['colluding_nf_reports']=2
 elif kind=='replay': meta['replayed']=True
 return tuple(r),false,meta

def features(t,kind,rng):
 load={'normal':.2,'overload':.9,'mixed':.6,'inflate':.5,'hide':.55,'scope':.45,'replay':.25,'loss':.3,'epoch':.4,'collusion':.6,'witness_bad':.5}[kind]
 z=[]
 for x in t:
  e=1 if x in ('E','P') else .2 if x=='D' else 0; lat=max(1,40+220*load+160*e+rng.gauss(0,20)); retry=.8 if x=='D' else .25 if x=='P' else .05
  z.append([max(0,load+rng.gauss(0,.08)),max(0,e+rng.gauss(0,.05)),lat,max(0,retry+rng.gauss(0,.04))])
 return z
def normal_sample(r,n):
 return [[max(0,r.gauss(.2,.07)),max(0,r.gauss(.03,.03)),max(1,r.gauss(70,18)),max(0,r.gauss(.05,.03))] for _ in range(n)]
def model(seed):
 train=normal_sample(random.Random(seed+91),1000)
 cal_x=normal_sample(random.Random(seed+92),1000)
 m=IsolationForest(n_estimators=128,random_state=seed).fit(train)
 cal=sorted(-m.decision_function(cal_x))
 return m,cal
def ranks(pack,X):
 import bisect
 m,cal=pack; s=-m.decision_function(X); return [(1+bisect.bisect_right(cal,float(x)))/(len(cal)+1) for x in s]
def vector_count(ds,skip=None):
 dp={(0,0,0,0):1}
 for idx,d in enumerate(ds):
  if idx==skip: continue
  nd=defaultdict(int)
  for v,n in dp.items():
   for x in d: nd[add(v,one(x))]+=n
  dp=nd
 return dp
def delta_report(ds,i,r):
 if len(ds[i])<=1:return 0
 other=vector_count(ds,i); total_other=sum(other.values())
 a_by={}; b_by={}
 for x in ds[i]:
  ex=one(x); target=tuple(r[j]-ex[j] for j in range(4))
  a=other.get(target,0); a_by[x]=a; b_by[x]=total_other-a
 A=sum(a_by.values()); B=sum(b_by.values())
 if A==0 or B==0:return 0
 separated=A*B-sum(a_by[x]*b_by[x] for x in ds[i])
 return separated/(A*B)
def policy(t,ds0,r,X,Q,name,budget,rng):
 ds=[set(x) for x in ds0]; u=[i for i,d in enumerate(ds) if len(d)>1]; cost={i:450+25*(i%11)+int(X[i][2]) for i in u}; spent=q=0
 v,_=exact(ds,r)
 if v=='REPORT_INCONSISTENT': return v,0,0
 if name=='random': order=u[:]; rng.shuffle(order)
 elif name=='uniform': order=sorted(u)
 elif name=='ml_only': order=sorted(u,key=lambda i:(-Q[i]/cost[i],i))
 else: order=[]
 audit=u[:]; rng.shuffle(audit); mandatory=int(.2*budget) if name=='proposed' else 0
 while u:
  if name=='proposed':
   if spent<mandatory and audit:
    i=audit.pop(0)
    if i not in u: continue
   else:i=max(u,key=lambda j:(.05+Q[j])*delta_report(ds,j,r)/cost[j])
  else:
   while order and order[0] not in u:order.pop(0)
   if not order:break
   i=order.pop(0)
  if spent+cost[i]>budget:break
  spent+=cost[i];q+=1;ds[i]={t[i]};u.remove(i);v,_=exact(ds,r)
  if v=='REPORT_INCONSISTENT':break
 return v,spent,q

def selftest(seed):
 r=random.Random(seed); c={'honest_no_false_refutation':0,'hierarchy_equals_central':0,'naive_false_accusations':0,'interval_counterexample':2,'epoch_key_uniqueness':2}
 for _ in range(800):
  n=r.randint(1,9);t=[r.choice(O) for _ in range(n)];o=[r.random()>.35 for _ in t];d=domains(t,o);rv=vec(t)
  assert exact(d,rv)[0]=='NOT_REFUTED';c['honest_no_false_refutation']+=1
  assert exact(d,rv)[0]==hier(d,rv,r.randint(1,4))[0];c['hierarchy_equals_central']+=1
  c['naive_false_accusations']+=naive(d,rv[0])=='REPORT_INCONSISTENT'
 assert len({(1,1),(2,1)})==2
 return c
def ci(v):
 if not v:return (None,None)
 n=len(v); p=statistics.mean(v); z=1.96
 den=1+z*z/n
 center=(p+z*z/(2*n))/den
 half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
 return max(0,center-half),min(1,center+half)
def writecsv(p,rows):
 if not rows:Path(p).write_text('');return
 with open(p,'w',newline='') as f:w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)

def main():
 a=argparse.ArgumentParser();a.add_argument('--events');a.add_argument('--outdir',default='artifacts/analysis');a.add_argument('--seed',type=int,default=20261025);a.add_argument('--replicates',type=int,default=80);a.add_argument('--attempts',type=int,default=24);a.add_argument('--self-test',action='store_true');x=a.parse_args();checks=selftest(x.seed)
 if x.self_test:print(json.dumps(checks,indent=2));return
 ev=json.loads(Path(x.events).read_text())['events']
 if not ev:raise SystemExit('network event set is empty; refusing to label synthetic data as a network experiment')
 rng=random.Random(x.seed);pack=model(x.seed);sc=['normal','overload','mixed','inflate','hide','scope','replay','loss','epoch','collusion','witness_bad'];dr=[];pr=[];t0=time.perf_counter();tracemalloc.start()
 for rep in range(x.replicates):
  for k in sc:
   t=truth(k,x.attempts,rng);obs=mask(k,len(t),rng);rk='normal' if k in ('loss','epoch') else k;rp,false,meta=report(t,rk);d=domains(t,obs)
   if k=='witness_bad':d=domains(['S' if y and q!='S' else q for q,y in zip(t,obs)],obs)
   X=features(t,k,rng);Q=ranks(pack,X);cen=exact(d,rp)[0];he=hier(d,rp)[0];assert cen==he
   vals={'ml_only_no_report_check':'NOT_REFUTED','naive_missing_is_failure':naive(d,rp[0]),'scalar_interval':interval(d,rp[0]),'central_exact':cen,'hierarchical_exact':he,'coordinate_intervals':box(d,rp)}
   if meta.get('replayed'):vals={q:'INSUFFICIENT_EVIDENCE' for q in vals}
   for name,v in vals.items():dr.append({'replicate':rep,'scenario':k,'detector':name,'false_report':int(false),'within_trust_model':int(k!='witness_bad'),'verdict':v,'detected':int(false and v=='REPORT_INCONSISTENT'),'false_accusation':int((not false) and v=='REPORT_INCONSISTENT'),'unresolved_false':int(false and v!='REPORT_INCONSISTENT')})
   if false and not meta.get('replayed') and k!='witness_bad':
    costs=[450+25*(i%11)+int(X[i][2]) for i,y in enumerate(obs) if not y];avg=statistics.mean(costs or [700])
    for bq in (0,2,4,8,12):
     for pn in ('uniform','random','ml_only','proposed'):
      v,sp,nq=policy(t,d,rp,X,Q,pn,int(avg*bq),random.Random(x.seed+rep*1009+bq*37+len(pn)))
      pr.append({'replicate':rep,'scenario':k,'policy':pn,'budget_queries_equiv':bq,'spent_bytes':sp,'queries':nq,'detected':int(v=='REPORT_INCONSISTENT')})
 cur,peak=tracemalloc.get_traced_memory();tracemalloc.stop();elapsed=time.perf_counter()-t0
 ds=[]
 for name,rows in sorted(defaultdict(list,((n,[r for r in dr if r['detector']==n]) for n in sorted(set(r['detector'] for r in dr)))).items()):
  f=[r for r in rows if r['false_report'] and r['within_trust_model']];h=[r for r in rows if not r['false_report'] and r['within_trust_model']];v=[r['detected'] for r in f];lo,hi=ci(v);ds.append({'detector':name,'false_report_detection_rate':statistics.mean(v) if v else None,'detection_ci95_low':lo,'detection_ci95_high':hi,'false_accusation_rate':statistics.mean(r['false_accusation'] for r in h) if h else None,'unresolved_false_rate':statistics.mean(r['unresolved_false'] for r in f) if f else None})
 ps=[]
 for key in sorted(set((r['policy'],r['budget_queries_equiv']) for r in pr)):
  rows=[r for r in pr if (r['policy'],r['budget_queries_equiv'])==key];v=[r['detected'] for r in rows];lo,hi=ci(v);ps.append({'policy':key[0],'budget_queries_equiv':key[1],'detection_rate':statistics.mean(v),'ci95_low':lo,'ci95_high':hi,'mean_bytes':statistics.mean(r['spent_bytes'] for r in rows),'mean_queries':statistics.mean(r['queries'] for r in rows)})
 c=Counter(e['truth'] for e in ev);l=[e['latency_ms'] for e in ev if e.get('latency_ms') is not None];sid=defaultdict(set)
 for e in ev:sid[e['stream_id']].add(e['connection_epoch'])
 net={'attempts':len(ev),'outcome_counts':{o:c[o] for o in O},'connection_epochs':len(set(e['connection_epoch'] for e in ev)),'same_stream_id_across_epochs':any(len(z)>1 for z in sid.values()),'latency_ms_mean':statistics.mean(l) if l else None,'latency_ms_p95':sorted(l)[max(0,math.ceil(.95*len(l))-1)] if l else None}
 out=Path(x.outdir);out.mkdir(parents=True,exist_ok=True);summary={'network':net,'invariants':checks,'detectors':ds,'policies':ps,'analysis_wall_seconds':elapsed,'analysis_peak_python_bytes':peak,'seed':x.seed,'replicates':x.replicates,'attempts_per_scenario':x.attempts};Path(out/'summary.json').write_text(json.dumps(summary,indent=2));writecsv(out/'detector_trials.csv',dr);writecsv(out/'policy_trials.csv',pr);writecsv(out/'detector_summary.csv',ds);writecsv(out/'policy_summary.csv',ps)
 lines=['# Experiment result','','## Real Open5GS/UERANSIM trace',f"- CreateSMContext attempts: **{net['attempts']}**",f"- Outcomes: `{net['outcome_counts']}`",f"- HTTP/2 connection epochs: **{net['connection_epochs']}**",f"- Same stream ID in different epochs: **{net['same_stream_id_across_epochs']}**",'', 'Controlled error/redirect/loss/self-report cases below are labelled synthetic extensions; they are not presented as Open5GS failures.','','## Detector comparison','| detector | detection | 95% CI | false accusation | unresolved false |','|---|---:|---:|---:|---:|']
 for r in ds:
  f=lambda z:'n/a' if z is None else f'{z:.3f}';lines.append(f"| {r['detector']} | {f(r['false_report_detection_rate'])} | [{f(r['detection_ci95_low'])}, {f(r['detection_ci95_high'])}] | {f(r['false_accusation_rate'])} | {f(r['unresolved_false_rate'])} |")
 lines+=['','## Equal-budget policies','| policy | budget | detection | 95% CI | mean bytes | mean queries |','|---|---:|---:|---:|---:|---:|']
 for r in ps:lines.append(f"| {r['policy']} | {r['budget_queries_equiv']} | {r['detection_rate']:.3f} | [{r['ci95_low']:.3f}, {r['ci95_high']:.3f}] | {r['mean_bytes']:.1f} | {r['mean_queries']:.2f} |")
 lines+=['','## Guardrails','- `NOT_REFUTED` is compatibility, not proof of honesty.','- Witness compromise is outside the trust model and excluded from policy claims.','- Isolation Forest only prioritizes evidence; deterministic inconsistency is never overridden.','- A single CI topology/version pair does not establish general superiority.'];Path(out/'report.md').write_text('\n'.join(lines)+'\n');print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
