from __future__ import annotations

import math
import statistics
from dataclasses import dataclass

T975={1:12.706,2:4.303,3:3.182,4:2.776,5:2.571,6:2.447,7:2.365,8:2.306,9:2.262,10:2.228,11:2.201,12:2.179,13:2.160,14:2.145,15:2.131,16:2.120,17:2.110,18:2.101,19:2.093,20:2.086,21:2.080,22:2.074,23:2.069,24:2.064,25:2.060,26:2.056,27:2.052,28:2.048,29:2.045,30:2.042}

@dataclass(frozen=True)
class Summary:
    n:int; mean:float; std:float; ci95_low:float; ci95_high:float

def describe(values:list[float])->Summary:
    clean=[float(v) for v in values if v is not None and not math.isnan(float(v))]; n=len(clean)
    if n==0:
        nan=float("nan"); return Summary(0,nan,nan,nan,nan)
    mean=statistics.fmean(clean)
    if n==1: return Summary(1,mean,0.0,mean,mean)
    std=statistics.stdev(clean); critical=T975.get(n-1,1.96); half=critical*std/math.sqrt(n)
    return Summary(n,mean,std,mean-half,mean+half)

def auroc(labels:list[int],scores:list[float])->float:
    pairs=sorted(zip(scores,labels),key=lambda x:x[0]); n_pos=sum(labels); n_neg=len(labels)-n_pos
    if n_pos==0 or n_neg==0: return float("nan")
    rank_sum_pos=0.0; i=0
    while i<len(pairs):
        j=i+1
        while j<len(pairs) and pairs[j][0]==pairs[i][0]: j+=1
        avg_rank=((i+1)+j)/2.0; rank_sum_pos+=avg_rank*sum(label for _,label in pairs[i:j]); i=j
    return (rank_sum_pos-n_pos*(n_pos+1)/2.0)/(n_pos*n_neg)

def average_precision(labels:list[int],scores:list[float])->float:
    ordered=sorted(zip(scores,labels),key=lambda x:x[0],reverse=True); positives=sum(labels)
    if positives==0: return float("nan")
    tp=0; precision_sum=0.0
    for idx,(_,label) in enumerate(ordered,start=1):
        if label: tp+=1; precision_sum+=tp/idx
    return precision_sum/positives

def wilson_interval(successes:int,n:int,z:float=1.96)->tuple[float,float]:
    if n<=0: return float("nan"),float("nan")
    p=successes/n; denom=1.0+z*z/n; center=(p+z*z/(2*n))/denom; half=z*math.sqrt((p*(1-p)+z*z/(4*n))/n)/denom
    return max(0.0,center-half),min(1.0,center+half)

def hedges_g(group_a:list[float],group_b:list[float])->float:
    a=[float(x) for x in group_a if x is not None and not math.isnan(float(x))]; b=[float(x) for x in group_b if x is not None and not math.isnan(float(x))]
    if len(a)<2 or len(b)<2: return float("nan")
    va=statistics.variance(a); vb=statistics.variance(b); df=len(a)+len(b)-2
    if df<=0: return float("nan")
    pooled_var=((len(a)-1)*va+(len(b)-1)*vb)/df
    if pooled_var<=0: return 0.0 if math.isclose(statistics.fmean(a),statistics.fmean(b)) else float("inf")
    d=(statistics.fmean(a)-statistics.fmean(b))/math.sqrt(pooled_var); correction=1.0-3.0/(4.0*(len(a)+len(b))-9.0)
    return correction*d
