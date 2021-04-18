set -e
PROJECT_ROOT=$(pwd)
cd "$PROJECT_ROOT/deploy/keygen"
go build
mkdir "$PROJECT_ROOT/deploy/2-org-1-orderer/keys"
./keygen 2 "$PROJECT_ROOT/deploy/2-org-1-orderer/keys"
cd "$PROJECT_ROOT/deploy/2-org-1-orderer"
echo "" > "$PROJECT_ROOT/log/2_node_eval.log"
./restartNetwork.sh 2>&1 | tee -a $PROJECT_ROOT/log/2_node_eval.log

cd "$PROJECT_ROOT/app"
npm install
export NUM_ORGS=2
./run.sh 2>&1 | tee -a "$PROJECT_ROOT/log/2_node_eval.log"
