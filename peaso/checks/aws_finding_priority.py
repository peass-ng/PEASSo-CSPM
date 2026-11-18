"""Prioritize captured ingress declarations without claiming a live connection."""
SENSITIVE = {21,22,23,135,139,445,1433,1521,2049,2375,2376,3306,3389,5432,5439,5900,5985,5986,6379,9200,9300,11211,27017}
WITNESS_IDS = {'aws.nist.ec2_instance_effective_public_reachability','aws_fedramp_ec2_effective_public_exposure'}


def contextual_severity(finding, default=None):
    baseline=default or finding.get('severity','medium')
    if finding.get('provider')!='aws' or finding.get('status')!='FAIL':return baseline
    cid=finding.get('check_id');e=finding.get('evidence')
    if not isinstance(e,dict):return baseline
    if cid=='aws.htbp.elbv2.mtls_no_shared_cdn_origin_ca':
        # A shared CDN CA on an internal ALB is only reachable from inside the network.
        return 'low' if e.get('internet_facing') is False else baseline
    ranges=[]
    if cid=='aws.ec2.restrict_internet_ingress':
        entries=e.get('internet_ingress')
        if not isinstance(entries,list) or not entries:return baseline
        for r in entries:
            if not isinstance(r,dict):return baseline
            if r.get('protocol')=='-1':
                ranges.append((0,65535));continue
            if r.get('protocol') not in ('tcp','6'):return baseline
            a,b=r.get('from_port'),r.get('to_port')
            if type(a) is not int or type(b) is not int or not 0<=a<=b<=65535:return baseline
            ranges.append((a,b))
    elif cid in WITNESS_IDS:
        proof=e.get('configured_path_witness')
        if not isinstance(proof,dict) or proof.get('protocol') not in ('tcp','6'):return baseline
        p=proof.get('destination_port')
        if type(p) is not int or not 0<=p<=65535:return baseline
        ranges=[(p,p)]
    else:return baseline
    if any(a<=p<=b for a,b in ranges for p in SENSITIVE):return 'high'
    if all(a==b and a in (80,443) for a,b in ranges):return 'medium'
    return baseline
