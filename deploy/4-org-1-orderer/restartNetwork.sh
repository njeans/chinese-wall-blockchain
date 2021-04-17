set -e
./network.sh down -s couchdb && ./network.sh up createChannel  -i "2.0.0" -ca -s couchdb && ./network.sh deployCC
