genCategory() {
  org=$1
  num=$2
  numc=$3
  uni=$4
  for i in $(seq 1 $num);
  do
  	cat="$uni-testcat-Org$org-$i"
  	new_category $cat $org
  done
  for i in $(seq 1 $num);
  do
    for j in $(seq 1 $numc);
    do
    	cat="$uni-testcat-Org$org-$i"
      sub="$uni-testsub-Org$org-$i-$j"
    	new_subject $cat $sub $org
    done
  done
  for i in $(seq 1 $num);
  do
    for j in $(seq 1 $numc);
    do
    	cat="$uni-testcat-Org$org-$i"
      sub="$uni-testsub-Org$org-$i-$j"
      data="$uni-testdata-Org$org-$i-$j"
    	new_data $cat $sub $data $org
    done
  done
}

genRequests() {
  org=$1
  num=$2
  uni=$3
  for i in $(seq 1 $num);
  do
    cat="$uni-testcat-Org$org-$i"
    sub="$uni-testsub-Org$org-$i-1"
    request_subject $cat $sub $org
    sleep $4
  done
}

getResults() {
  line=$(docker ps | grep "peer0.org$1.example.com-cwcc")
  name=$(echo $line | awk '{print $NF}')
  docker cp $name:/tmp/data "org$1.data"
}

runEvaluate() {
  genCategory 2 100 2 .5
  genRequests 1 100 .5 .5
}
