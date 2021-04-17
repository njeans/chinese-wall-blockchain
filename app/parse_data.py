import os
project_root=os.environ['PROJECT_ROOT']
if not os.path.exists(project_root+"app/data"):
    os.makedirs(project_root+"app/data")
points = [".1",".2",".4", ".8", "1.6", "3.2", "6.4", "12.8"]
for p in points:
    try:
        with open(project_root+"/app/data/org2_"+str(p)+".data") as f:
            data = f.read()
        subjects = {}
        subjectlist = []
        for l in data.split("\n"):
            if str(p)+"-testcat" not in l:
                continue
            s = l.split(",")
            if len(s) < 4:
                continue
            cat = s[0]
            sub=s[1]
            type = s[2]
            time = s[3]
            subjectlist.append(cat+sub)
            subjects[cat+sub+type] = time
        total = 0
        over_time = []
        for name in subjectlist:
            try:
                # print(name)
                start =subjects[name+"request_subject"]
                end = subjects[name+"read_response"]
                dur = int(end) - int(start)
                total += dur
                over_time.append((name,dur))
            except Exception as e:
                print("error",e)
                pass
        print(p,",",(total*.000000001)/len(subjectlist))
        over_time.sort(key = lambda x: x[0])
        # print("\n".join([str(p)+","+str(x[1]*.000000001) for x in over_time]))
        # print(len(subjectlist))
        # break
    except Exception as e:
        print("error",e)
        pass
