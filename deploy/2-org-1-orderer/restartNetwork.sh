set -e
./network.sh down -s couchdb && ./network.sh up createChannel -ca -i "2.0.0" -s couchdb && ./network.sh deployCC
