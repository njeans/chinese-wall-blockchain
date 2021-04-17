testSetup() {
  org=$1
	otherorg=$2
  echo
  echo "***********************************************************************************"
  echo "*************************** testSetup $@ ***************************"
  echo "***********************************************************************************"
  echo

	query $org '"get_pub","Org'${org}'MSP"'
  query $otherorg '"get_pub","Org'${org}'MSP"'
	query $org '"get_priv"'
}

testNewCategory() {
  org=$1
	otherorg=$2
  echo
  echo "***********************************************************************************"
  echo "*************************** testNewCategory $@ ***************************"
  echo "***********************************************************************************"
  echo

	cat="testcat-Org$org-1"
	new_category $cat $org
	sleep 3
	out1="$(list_my_categories $org)"
	res1=$(echo $out1 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyOutput testNewCategory $cat $res1

	out2="$(list_my_categories $otherorg)"
	res2=$(echo $out2 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyNotOutput testNewCategory $cat $res2
}

test1NewSubject() {
  org=$1
	otherorg=$2
  echo
  echo "***********************************************************************************"
  echo "*************************** test1NewSubject $@ ***************************"
  echo "***********************************************************************************"
  echo

	cat="testcat-Org$org-1"
	sub="testsub-Org$org-1"
	new_subject $cat $sub $org
	sleep 3
	out1="$(list_my_subjects $cat $org)"
	res1=$(echo $out1 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyOutput test1NewSubject $sub $res1

	out2="$(list_my_subjects $cat $otherorg)"
	res2=$(echo $out2 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyNotOutput test1NewSubject $sub $res2
}

test2NewSubject() {
  org=$1
	otherorg=$2
  echo
  echo "***********************************************************************************"
  echo "*************************** test2NewSubject $@ ***************************"
  echo "***********************************************************************************"
  echo

	cat="testcat-Org$org-1"
	sub="testsub-Org$org-2"
	new_subject $cat $sub $org
	sleep 3
	out1="$(list_my_subjects $cat $org)"
	res1=$(echo $out1 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyOutput test2NewSubject $sub $res1

	out2="$(list_my_subjects $cat $otherorg)"
	res2=$(echo $out2 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyNotOutput test2NewSubject $sub $res2
}

test1NewData() {
  org=$1
	otherorg=$2
  echo
  echo "***********************************************************************************"
  echo "*************************** test1NewData $@ ***************************"
  echo "***********************************************************************************"
  echo

	cat="testcat-Org$org-1"
	sub="testsub-Org$org-1"
	data="testdata-Org$org-1"
	new_data $cat $sub $data $org
	sleep 3
	out1="$(list_my_data $cat $sub $org)"
	res1=$(echo $out1 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyOutput test1NewData $data $res1

	out2="$(list_my_data $cat $sub $otherorg)"
	res2=$(echo $out2 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyNotOutput test1NewData $data $res2
}

test2NewData() {
	org=$1
	otherorg=$2
  echo
  echo "***********************************************************************************"
  echo "*************************** test2NewData $@ ***************************"
  echo "***********************************************************************************"
  echo

	cat="testcat-Org$org-1"
	sub="testsub-Org$org-1"
	data="testdata-Org$org-2"
	new_data $cat $sub $data $org
	sleep 3
	out1="$(list_my_data $cat $sub $org)"
	res1=$(echo $out1 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyOutput test2NewData $data $res1

	out2="$(list_my_data $cat $sub $otherorg)"
	res2=$(echo $out2 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyNotOutput test2NewData $data $res2
}

testGetPubCategory() {
  orgs="${@}"
  echo
  echo "***********************************************************************************"
  echo "*************************** testGetPubCategory $@ ***************************"
  echo "***********************************************************************************"
  echo

  # declare -a cats
  for org in $orgs
  do
    cats=("${cats[@]}" "testcat-Org${org}-1")
  done
  for org in $orgs
  do
    out1=$(list_categories_pub $org)
    res1=$(echo $out1 |  sed 's/^.*payload:"//; s/" ===.*$//' )
    for cat in "${cats[@]}"
    do
      verifyOutput testGetPubCategory $cat $res1
    done
  done
}

testGetPubSubject() {
  orgs="${@}"
  echo
  echo "***********************************************************************************"
  echo "*************************** testGetPubSubject $@ ***************************"
  echo "***********************************************************************************"
  echo

  for catorg in $orgs
  do
    cat="testcat-Org$catorg-1"
    subs=("testsub-Org$catorg-1" "testsub-Org$catorg-2")
    for org in $orgs
    do
      out1=$(list_subjects_pub $cat $org)
      res1=$(echo $out1 |  sed 's/^.*payload:"//; s/" ===.*$//' )
      for sub in "${subs[@]}"
      do
        verifyOutput testGetPubCategory $sub $res1
      done
    done
  done
}

testRequestAccessApprove() {
  org=$1
	otherorg=$2
  echo
  echo "***********************************************************************************"
  echo "*************************** testRequestAccessApprove $@ ***************************"
  echo "***********************************************************************************"
  echo

	cat="testcat-Org$otherorg-1"
  sub="testsub-Org$otherorg-1"
  expdata=("testdata-Org$otherorg-1" "testdata-Org$otherorg-2")

	request_subject $cat $sub $org
	sleep 3
  respond_request $cat $sub "Org${org}MSP" $otherorg
  sleep 3
  read_response $cat $sub $org
  sleep 3

	out1="$(list_categories_priv $org)"
	res1=$(echo $out1 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyOutput testRequestAccesApprove $cat $res1

  out2="$(list_subjects_priv $cat $org)"
	res2=$(echo $out2 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyOutput testRequestAccesApprove $sub $res2

  out3="$(list_data_priv $cat $sub $org)"
	res3=$(echo $out3 |  sed 's/^.*payload:"//; s/" ===.*$//' )

  for data in "${expdata[@]}"
  do
    verifyOutput testRequestAccesApprove $data $res3
  done

}

testRequestAccessDeny() {
  org=$1
	otherorg=$2
  echo
  echo "***********************************************************************************"
  echo "*************************** testRequestAccessDeny $@ ***************************"
  echo "***********************************************************************************"
  echo

	cat="testcat-Org$otherorg-1"
  sub="testsub-Org$otherorg-2"

	request_subject $cat $sub $org
	sleep 3
  respond_request $cat $sub "Org${org}MSP" $otherorg
  sleep 5
  read_response $cat $sub $org
  sleep 5

	out1="$(list_subjects_priv $cat $org)"
	res1=$(echo $out1 |  sed 's/^.*payload:"//; s/" ===.*$//' )
	verifyNotOutput testRequestAccessDeny $sub $res1
}

runAllTests() {
  testSetup 1 2
  testSetup 2 1
  testNewCategory 1 2
  testNewCategory 2 1
  test1NewSubject 1 2
  test1NewSubject 2 1
  test2NewSubject 1 2
  test2NewSubject 2 1
  test1NewData 1 2
  test1NewData 2 1
  test2NewData 1 2
  test2NewData 2 1
  testGetPubCategory 1 2
  testGetPubSubject 1 2
  testRequestAccessApprove 1 2
  testRequestAccessApprove 2 1
  testRequestAccessDeny 1 2
  testRequestAccessDeny 2 1
}
