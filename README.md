# Chinese Wall AC on Hyperledger Blockchain
## Abstract
Blockchains are a powerful technology that can be leveraged to allow for accountability and collaboration between multiple parties. With the popularity of permissioned blockchain systems such as Hyperledger Fabric for enterprise use cases, strong expressive access control policies are a necessary tool to facilitate sharing of data and encourage trust among all participants. 

The ability to revoke access to data submitted on the blockchain is desirable due to it's flexibility with respect to security guarantees. We create an implementation of this ability and apply it to a Chinese wall access control model use case. We run benchmarks on this implementation to measure it's usability.

Full writeup on my website
<https://www.nerla.me/projects>

## Prerequisites
* Docker & Docker compose
* golang and set `GOPATH`
* python3
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
