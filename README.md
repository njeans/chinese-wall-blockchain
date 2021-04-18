# cs563
## Prerequisites
* Docker & Docker compose
* golang and set `GOPATH`
* Node & npm
* Fabric Prereqs here: <https://hyperledger-fabric.readthedocs.io/en/latest/prereqs.html>
* Fabric Binaries for version 2.0.0:
  * From: <https://hyperledger-fabric.readthedocs.io/en/latest/install.html>

`cd $GOPATH/src/github.com/<github userid>`

`curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.0.0 `

Add to binaries to path:

`export PATH=$PATH:$GOPATH/src/github.com/<github userid>/fabric-samples/bin`

## Files
### app
 Contains the nodejs server that handles all responses to requests and reading those responses.
### chaincode
 Contains the chinese wall chaincode implementation
### deploy
 Contains deployment scripts for the networks and key generation
#### deploy/keygen
 Generate keys for all peers
#### deploy/2-org-1-orderer
 Scripts and artifacts to run network with 2 organizations and 1 orderer
#### deploy/4-org-1-orderer
 Scripts and artifacts to run network with 4 organizations and 1 orderer


## Run and test network
* `run_2.sh` run 2 node network and execute experiments
* `run_4.sh` run 4 node network and execute experiments

## Change experiment parameters
* `app/run_eval.sh`
* 2 Org network: `deploy/2-org-1-orderer/scripts/eval.sh`
* 4 Org network: `deploy/4-org-1-orderer/scripts/eval.sh`
