from swarmguard.reporting.stats import auroc, average_precision, describe


def test_describe_reports_sample_std_and_ci():
    s=describe([1.0,2.0,3.0,4.0,5.0])
    assert s.n==5
    assert round(s.mean,6)==3.0
    assert s.std>0
    assert s.ci95_low<s.mean<s.ci95_high


def test_perfect_classifier_metrics():
    labels=[0,0,1,1]; scores=[0.1,0.2,0.8,0.9]
    assert auroc(labels,scores)==1.0
    assert average_precision(labels,scores)==1.0
