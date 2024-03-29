
CHANNEL_NAME="$1"
CC_SRC_LANGUAGE="$2"
VERSION="$3"
DELAY="$4"
MAX_RETRY="$5"
VERBOSE="$6"
: ${CHANNEL_NAME:="mychannel"}
: ${CC_SRC_LANGUAGE:="golang"}
: ${VERSION:="1"}
: ${DELAY:="3"}
: ${MAX_RETRY:="5"}
: ${VERBOSE:="false"}
CC_SRC_LANGUAGE=`echo "$CC_SRC_LANGUAGE" | tr [:upper:] [:lower:]`

FABRIC_CFG_PATH=$PWD/../config/
echo FABRIC_CFG_PATH $FABRIC_CFG_PATH
CC_PATH=../../chaincode/chinese_wall/collections_config_4orgs.json
POLICY="OR('Org1MSP.member','Org2MSP.member','Org3MSP.member','Org4MSP.member')"
KEY_PATH="./keys"

if [ "$CC_SRC_LANGUAGE" = "go" -o "$CC_SRC_LANGUAGE" = "golang" ] ; then
	CC_RUNTIME_LANGUAGE=golang
	CC_SRC_PATH="../../chaincode/chinese_wall/go/"

	echo Vendoring Go dependencies ...
	pushd ../../chaincode/chinese_wall/go
	GO111MODULE=on go mod vendor
	popd
	echo Finished vendoring Go dependencies
else
	echo The chaincode language ${CC_SRC_LANGUAGE} is not supported by this script
	echo Supported chaincode languages are: go, java, javascript, and typescript
	exit 1
fi

# import utils
. scripts/envVar.sh
. scripts/util.sh
. scripts/tests.sh

packageChaincode() {
  ORG=$1
  setGlobals $ORG
  set -x
  peer lifecycle chaincode package cwcc.tar.gz --path ${CC_SRC_PATH} --lang ${CC_RUNTIME_LANGUAGE} --label cwcc_${VERSION} >&log.txt
  res=$?
  set +x
  cat log.txt
  verifyResult $res "Chaincode packaging on peer0.org${ORG} has failed"
  echo "===================== Chaincode is packaged on peer0.org${ORG} ===================== "
  echo
}

# installChaincode PEER ORG
installChaincode() {
  ORG=$1
  setGlobals $ORG
  set -x
  peer lifecycle chaincode install cwcc.tar.gz >&log.txt
  res=$?
  set +x
  cat log.txt
  verifyResult $res "Chaincode installation on peer0.org${ORG} has failed"
  echo "===================== Chaincode is installed on peer0.org${ORG} ===================== "
  echo
}

# queryInstalled PEER ORG
queryInstalled() {
  ORG=$1
  setGlobals $ORG
  set -x
  peer lifecycle chaincode queryinstalled >&log.txt
  res=$?
  set +x
  cat log.txt
	PACKAGE_ID=$(sed -n "/cwcc_${VERSION}/{s/^Package ID: //; s/, Label:.*$//; p;}" log.txt)
  verifyResult $res "Query installed on peer0.org${ORG} has failed"
  echo PackageID is ${PACKAGE_ID}
  echo "===================== Query installed successful on peer0.org${ORG} on channel ===================== "
  echo
}

# approveForMyOrg VERSION PEER ORG
approveForMyOrg() {
	parsePeerConnectionParameters $@
  ORG=$1
  setGlobals $ORG
	echo "PEER_CONN_PARMS $PEER_CONN_PARMS"
  set -x
	peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --channelID $CHANNEL_NAME  --name cwcc --version ${VERSION} --collections-config ${CC_PATH} --signature-policy ${POLICY} --package-id $PACKAGE_ID --sequence ${VERSION} --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA $PEER_CONN_PARMS >&log.txt
	res=$?
  set +x
  cat log.txt
  verifyResult $res "Chaincode definition approved on peer0.org${ORG} on channel '$CHANNEL_NAME' failed"
  echo "===================== Chaincode definition approved on peer0.org${ORG} on channel '$CHANNEL_NAME' ===================== "
  echo
}

# checkCommitReadiness VERSION PEER ORG
checkCommitReadiness() {
  ORG=$1
  shift 1
  setGlobals $ORG
  echo "===================== Checking the commit readiness of the chaincode definition on peer0.org${ORG} on channel '$CHANNEL_NAME'... ===================== "
	local rc=1
	local COUNTER=1
	# continue to poll
  # we either get a successful response, or reach MAX RETRY
	while [ $rc -ne 0 -a $COUNTER -lt $MAX_RETRY ] ; do
    sleep $DELAY
    echo "Attempting to check the commit readiness of the chaincode definition on peer0.org${ORG} secs"
    set -x
		peer lifecycle chaincode checkcommitreadiness --channelID $CHANNEL_NAME --name cwcc --version ${VERSION} --sequence ${VERSION} --signature-policy ${POLICY} --output json --collections-config ${CC_PATH}  >&log.txt
    res=$?
    set +x
    let rc=0
    for var in "$@"
    do
      grep "$var" log.txt &>/dev/null || let rc=1
    done
		COUNTER=$(expr $COUNTER + 1)
	done
  cat log.txt
  if test $rc -eq 0; then
    echo "===================== Checking the commit readiness of the chaincode definition successful on peer0.org${ORG} on channel '$CHANNEL_NAME' ===================== "
  else
    echo "!!!!!!!!!!!!!!! After $MAX_RETRY attempts, Check commit readiness result on peer0.org${ORG} is INVALID !!!!!!!!!!!!!!!!"
    echo
    exit 1
  fi
}

# commitChaincodeDefinition VERSION PEER ORG (PEER ORG)...
commitChaincodeDefinition() {
  parsePeerConnectionParameters $@
  res=$?
  verifyResult $res "Invoke transaction failed on channel '$CHANNEL_NAME' due to uneven number of peer and org parameters "

  # while 'peer chaincode' command can get the orderer endpoint from the
  # peer (if join was successful), let's supply it directly as we know
  # it using the "-o" option
  set -x
	echo "PEER_CONN_PARMS $PEER_CONN_PARMS"
	peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --channelID $CHANNEL_NAME --name cwcc --version ${VERSION} --sequence ${VERSION} --collections-config ${CC_PATH} --signature-policy ${POLICY} --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA $PEER_CONN_PARMS >&log.txt
  res=$?
  set +x
  cat log.txt
  verifyResult $res "Chaincode definition commit failed on peer0.org${ORG} on channel '$CHANNEL_NAME' failed"
  echo "===================== Chaincode definition committed on channel '$CHANNEL_NAME' ===================== "
  echo
}

# queryCommitted ORG
queryCommitted() {
  ORG=$1
  setGlobals $ORG
  EXPECTED_RESULT="Version: ${VERSION}, Sequence: ${VERSION}, Endorsement Plugin: escc, Validation Plugin: vscc"
  echo "===================== Querying chaincode definition on peer0.org${ORG} on channel '$CHANNEL_NAME'... ===================== "
	local rc=1
	local COUNTER=1
	# continue to poll
  # we either get a successful response, or reach MAX RETRY
	while [ $rc -ne 0 -a $COUNTER -lt $MAX_RETRY ] ; do
    sleep $DELAY
    echo "Attempting to Query committed status on peer0.org${ORG}, Retry after $DELAY seconds."
    set -x
    peer lifecycle chaincode querycommitted --channelID $CHANNEL_NAME --name cwcc >&log.txt
    res=$?
    set +x
		test $res -eq 0 && VALUE=$(cat log.txt | grep -o '^Version: [0-9], Sequence: [0-9], Endorsement Plugin: escc, Validation Plugin: vscc')
    test "$VALUE" = "$EXPECTED_RESULT" && let rc=0
		COUNTER=$(expr $COUNTER + 1)
	done
  echo
  cat log.txt
  if test $rc -eq 0; then
    echo "===================== Query chaincode definition successful on peer0.org${ORG} on channel '$CHANNEL_NAME' ===================== "
		echo
  else
    echo "!!!!!!!!!!!!!!! After $MAX_RETRY attempts, Query chaincode definition result on peer0.org${ORG} is INVALID !!!!!!!!!!!!!!!!"
    echo
    exit 1
  fi
}

setup() {
	## at first we package the chaincode
	packageChaincode 1

	## Install chaincode on peer0.org1 and peer0.org2
	installChaincode 1
	installChaincode 2
	installChaincode 3
	installChaincode 4

	## query whether the chaincode is installed
	queryInstalled 1

	sleep 3

	## approve the definition
	approveForMyOrg 1
	approveForMyOrg 2
	approveForMyOrg 3
	approveForMyOrg 4

	sleep 3

	## check whether the chaincode definition is ready to be committed
	## expect them both to have approved
	checkCommitReadiness 1 "\"Org1MSP\": true" "\"Org2MSP\": true" "\"Org3MSP\": true" "\"Org4MSP\": true"
	checkCommitReadiness 2 "\"Org1MSP\": true" "\"Org2MSP\": true" "\"Org3MSP\": true" "\"Org4MSP\": true"
	checkCommitReadiness 3 "\"Org1MSP\": true" "\"Org2MSP\": true" "\"Org3MSP\": true" "\"Org4MSP\": true"
	checkCommitReadiness 4 "\"Org1MSP\": true" "\"Org2MSP\": true" "\"Org3MSP\": true" "\"Org4MSP\": true"
	sleep 3
	## now that we know for sure both orgs have approved, commit the definition
	commitChaincodeDefinition 1 2 3 4

	## query on both orgs to see that the definition committed successfully
	queryCommitted 1
	queryCommitted 2
	queryCommitted 3
	queryCommitted 4

	## Invoke the chaincode
	chaincodeInvokeInit 1
	chaincodeInvokeInit 2
	chaincodeInvokeInit 3
	chaincodeInvokeInit 4
}

setup
sleep 3
# # ./../../app/run.sh &
# # runAllTests

# new_category "cat11" 1
# sleep 3
# new_subject "cat11" "sub11" 1
# sleep 3

# request_subject "cat11" "sub11" 2

# new_category "cat21" 2
# sleep 3
#
# new_subject "cat21" "sub21" 2
# sleep 3

# request_subject "cat21" "sub21" 1


exit 0
