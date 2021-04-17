# cs563
## Prerequisites
* Docker
* golang

## app
 Contains the nodejs server that handles all responses to requests and reading those responses.
## chaincode
 Contains the chinese wall chaincode implementation

## deploy
 Contains deployment scripts for the networks
## Run the network and tests
### 2 nodes
`cd deploy/2-org-1-orderer`
`./restartNetwork.sh`

### 4 nodes
`cd deploy/4-org-1-orderer`
`./restartNetwork.sh`

## Run evaluation
### 2 nodes
After starting the network

`cd app`
`export NUM_ORGS=2`
`./run_2.sh &`

### 4 nodes

`cd ../app`
`export NUM_ORGS=4`
`./run_4.sh &`
