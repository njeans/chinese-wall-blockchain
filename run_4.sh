cd deploy
cd keygen
go build
./keygen 4 "$(pwd)/../4-org-1-orderer/keys"
cd ../4-org-1-orderer
./restartNetwork.sh

cd ../../app
export NUM_ORGS=4
./run4.sh
