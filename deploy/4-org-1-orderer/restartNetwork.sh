set -e
sudo ./network.sh down -s couchdb && ./network.sh up createChannel -ca -s couchdb && ./network.sh deployCC
