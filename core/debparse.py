import re,sys,json
LINE=re.compile(r'^\s+(?:\[(\w[\w-]*)\]\s+)?-\s+(\S+)\s*(.*)$')
def parse(path):
    """returns dict cve -> {'nfu':bool,'desc':str,'entries':[(release or 'sid', pkg, status, note)], 'notes':[...]}"""
    out={}; cur=None
    with open(path,encoding='utf-8',errors='replace') as f:
        for ln in f:
            if ln.startswith('CVE-'):
                m=re.match(r'^(CVE-\d{4}-(?:\d+|XXXX))\s*(.*)$',ln.rstrip('\n'))
                cid=m.group(1); 
                if cid.endswith('XXXX'): cid=cid+'#'+m.group(2)[:60]
                cur={'desc':m.group(2),'nfu':False,'entries':[],'notes':[],'other':[]}
                out[cid]=cur; continue
            if cur is None: continue
            s=ln.rstrip('\n')
            if s.strip().startswith('NOT-FOR-US'): cur['nfu']=True; continue
            if s.strip().startswith('NOTE:'): cur['notes'].append(s.strip()[5:].strip()); continue
            m=LINE.match(s)
            if m:
                rel=m.group(1) or 'sid'; pkg=m.group(2); rest=m.group(3).strip()
                mm=re.match(r'^<([\w-]+)>\s*(?:\((.*)\))?',rest)
                if mm: st=mm.group(1); note=mm.group(2) or ''
                else:
                    vm=re.match(r'^(\S+)\s*(?:\((.*)\))?',rest)
                    st='fixed:'+(vm.group(1) if vm else rest); note=(vm.group(2) or '') if vm else ''
                cur['entries'].append((rel,pkg,st,note))
            else:
                cur['other'].append(s.strip())
    return out
if __name__=='__main__':
    d=parse(sys.argv[1]); print(len(d))
