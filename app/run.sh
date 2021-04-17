set -e
set -x
rm -rf wallet/*
node enrollAdmin 1 2-org-1-orderer
node registerUser 1 2-org-1-orderer
node enrollAdmin 2 2-org-1-orderer
node registerUser 2 2-org-1-orderer
node server 1 2-org-1-orderer 2>&1 | tee server1.log &
node server 2 2-org-1-orderer 2>&1 | tee server2.log &
./run_eval.sh
python parse_data.py > data.csv
cat data.csv
