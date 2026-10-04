from swarmguard.detector.model import RunRiskState
from swarmguard.experiment.policies import base36_prefix


def _event(i,family,key,numeric,diagnostic=False):
    return {"ts":str(1000+i*0.01),"identity":f"u{i}","family":family,"resource_key":key,"numeric_key":"" if numeric is None else str(numeric),"diagnostic":"1" if diagnostic else "0"}


def test_collective_pattern_scores_higher_than_hotspot_pattern():
    benign=RunRiskState("b",threshold=.72,min_events=30)
    coordinated=RunRiskState("c",threshold=.72,min_events=30)
    for i in range(300):
        family=("ticket","permit_prefix","zone")[i%3]
        if family=="ticket":
            benign.update(_event(i,family,str(i%100),i%100))
            v=int(((i//3)+0.5)/100*50000); coordinated.update(_event(i,family,str(v),v))
        elif family=="permit_prefix":
            benign.update(_event(i,family,"A0",None))
            coordinated.update(_event(i,family,base36_prefix(((i//3)%100)*12),None))
        else:
            benign.update(_event(i,family,str(i%10),i%10,False))
            z=min(499,(i//3)*5); coordinated.update(_event(i,family,str(z),z,True))
    assert coordinated.score_peak>benign.score_peak
    assert coordinated.features()["namespace_span"]>benign.features()["namespace_span"]
