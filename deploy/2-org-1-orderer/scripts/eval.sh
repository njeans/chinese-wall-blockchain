findData() {
  cat=$1
  sub=$2
  data=$3
  org=$4

  local notfound=1

  while [ $notfound -ne 0 ] ; do
    out="$(list_my_data $cat $sub $org)"
    datas=$(echo $out |  sed 's/^.*payload:"//; s/" ===.*$//' )
    echo "-------------$data in $datas-----------------"

    if [[ $datas == *$data* ]]; then
      notfound=0
    else
      sleep 3
    fi
  done
}

findSub() {
  cat=$1
  sub=$2
  org=$3

  local notfound=1

  while [ $notfound -ne 0 ] ; do
    out="$(list_my_subjects $cat $org)"
    subs=$(echo $out |  sed 's/^.*payload:"//; s/" ===.*$//' )
    echo "-------------$sub in $subs-----------------"

    if [[ $subs == *$sub* ]]; then
      notfound=0
    else
      sleep 3
    fi
  done
}

findCat() {
  cat=$1
  org=$2

  notfound=1

  while [ $notfound -ne 0 ] ; do
    out="$(list_my_categories $org)"
    cats=$(echo $out |  sed 's/^.*payload:"//; s/" ===.*$//' )
    echo "-------------$cat in $cats-----------------"

    if [[ $cats == *$cat* ]]; then
      notfound=0
    else
      sleep 3
    fi
  done
}

findSub_priv() {
  cat=$1
  sub=$2
  org=$3

  notfound=1
  cnt=0

  while [ $notfound -ne 0 ] ; do
    out="$(list_subjects_priv $cat $org)"
    subs=$(echo $out |  sed 's/^.*payload:"//; s/" ===.*$//' )
    echo "-------------$sub in $subs-----------------"

    if [[ $subs == *$sub* ]]; then
      notfound=0
    else
      sleep 3
      let cnt=$cnt+1
    fi

    if [ $cnt -ge 5 ] ; then
      echo "Timeout waiting for $cat in $sub"
      notfound=0
    fi
  done
}

genCategory() {
  org=$1
  num=$2
  uni=$3

  numSubs=2 #numer of subjects created per category

  for i in $(seq 1 $num);
  do
  	cat="$uni-testcat-Org$org-$i"
  	new_category $cat $org
  done

  for i in $(seq 1 $num);
  do
  	cat="$uni-testcat-Org$org-$i"
    findCat $cat $org
  done


  for j in $(seq 1 $numSubs);
  do
    for i in $(seq 1 $num);
    do
    	cat="$uni-testcat-Org$org-$i"
      sub="$uni-testsub-Org$org-$i-$j"
    	new_subject $cat $sub $org
    done

    for i in $(seq 1 $num);
    do
      cat="$uni-testcat-Org$org-$i"
      sub="$uni-testsub-Org$org-$i-$j"
      findSub $cat $sub $org
    done
  done

  for j in $(seq 1 $numSubs);
  do
    for i in $(seq 1 $num);
    do
    	cat="$uni-testcat-Org$org-$i"
      sub="$uni-testsub-Org$org-$i-$j"
      data="$uni-testdata-Org$org-$i-$j"
    	new_data $cat $sub $data $org
    done

    for i in $(seq 1 $num);
    do
    	cat="$uni-testcat-Org$org-$i"
      sub="$uni-testsub-Org$org-$i-$j"
      data="$uni-testdata-Org$org-$i-$j"
    	findData $cat $sub $data $org
    done
  done
}

genRequests() {
  org=$1
  orig=$2
  num=$3
  uni=$4
  rate=$5

  index=1
  max=$(echo "$num/$rate" | bc)
  echo $max
  for i in $(seq 1 $max);
  do
    cat="$uni-testcat-Org$orig-$index"
    sub="$uni-testsub-Org$orig-$index-1"
    for j in $(seq 1 $rate);
    do
      request_subject $cat $sub $org
      let index=$index+1
    done
    sleep $4
  done

  for i in $(seq 1 $num);
  do
    cat="$uni-testcat-Org$orig-$i"
    sub="$uni-testsub-Org$orig-$i-1"
    findSub_priv $cat $sub $org
  done
}

getResults() {
  line=$(docker ps | grep "peer0.org$1.example.com-cwcc")
  name=$(echo $line | awk '{print $NF}')
  docker cp "$name:/tmp/data" "data/org${1}_${2}.data"
  cat "data/org${1}_${2}.data"
}

runExperiment() {
  rate=$1
  sleepTime=$2
  numTxs=100
  creatorOrg=1
  requesterOrg=2
  genCategory $creatorOrg $numTxs $sleepTime
  genRequests $requesterOrg $creatorOrg $numTxs $sleepTime $rate
  getResults $requesterOrg $sleepTime
}

runEvaluate() {
  rate=$1

  for sleepTime in ".5" "1" "2" "4" ; do
    runExperiment $rate $sleepTime
  done

  # for sleepTime in ".1" ".2" ".4" ".8" "1.6" "3.2"; do
  #   runExperiment $rate $sleepTime
  # done

  # for testing
  # genCategory 1 3 2 2
  # genRequests 2 1 3 2
  # getResults 2 2
}
