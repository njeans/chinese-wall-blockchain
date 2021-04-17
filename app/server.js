/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const { Gateway, Wallets } = require('fabric-network');
const { Discoverer } = require('fabric-common');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

var myArgs = process.argv.slice(2);
var org = myArgs[0];
var networkName = myArgs[1];
console.log('myArgs: ', myArgs);

function parseEvent(err, event, blockNumber, transactionId, status) {
  if (err) {
    console.error(err);
    return;
  }

  //convert event to something we can parse
  event = event.payload.toString();
  event = JSON.parse(event)

  //where we output the TradeEvent
  console.log('************************ ReqEvent *******************************************************');
  console.log(`category: ${event.categoryName}`);
  console.log(`subject: ${event.subjectName}`);
  console.log(`org: ${event.org}`);
  console.log(`creator: ${event.creator}`);
  console.log(`Block Number: ${blockNumber} Transaction ID: ${transactionId} Status: ${status}`);
  console.log('************************ End ReqEvent ************************************');
}

async function getEvents() {

  try {

    let response;

    // load the network configuration
    const ccpPath = path.resolve(__dirname, '..', 'deploy', networkName, 'organizations', 'peerOrganizations', 'org' + org +'.example.com', 'connection-org'+ org +'.json');
    let ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

    // Create a new file system based wallet for managing identities.
    const walletPath = path.join(process.cwd(), "wallet", networkName + "_wallets", 'wallet' + org);
    const wallet = await Wallets.newFileSystemWallet(walletPath);
    console.log(`Wallet path: ${walletPath}`);

    // Check to see if we've already enrolled the user.
    const userName = 'server-user-org' + org;
    const identity = await wallet.get(userName);
    if (!identity) {
        console.log('An identity for the user '+userName+' does not exist in the wallet');
        console.log('Run the registerUser.js application before retrying');
        return;
    }
    // Create a new gateway for connecting to our peer node.
    const gateway = new Gateway();
    await gateway.connect(ccp, { wallet, identity: userName, discovery: { enabled: true, asLocalhost: true } });

    // Get the network (channel) our contract is deployed to.
    const network = await gateway.getNetwork('mychannel');

    // Get the contract from the network.
    const contract = network.getContract('cwcc');
    const channel = network.getChannel();
    channel.removeMsp("Org2MSP");
    const endorsers = channel.getEndorsers();
    const myendorsers = [];
    for (let endorser of endorsers) {
      if (endorser.mspid == "Org" + org + "MSP"){
        myendorsers.push(endorser);
      }
    }
    const reqName = "ReqEventOrg" + org + "MSP"
    console.log('addContractListener:' + reqName);
    const reqListener = async (event) => {
      if (event.eventName === reqName) {
          const details = JSON.parse(event.payload.toString('utf8'));
          console.log('************************ ReqEvent *******************************************************');
          console.log('details: %j', details);
          console.log('************************ End ReqEvent ************************************');
          console.log(`submit: respond_request ${"Org" + org}`);
          const tx = contract.createTransaction('respond_request');
          tx.setEndorsingPeers(myendorsers);
          tx.submit(details.categoryName, details.subjectName, details.creator).then(()=>{
            console.log('respond_request submited: %j', details);
          }).catch((err) => {
            console.error('respond_request error: %j error %j', details, err);
            reqListener(event);
          });
        }
    };
    const reqListenerPromise = contract.addContractListener(reqListener);

    const respName = "RespEventOrg" + org + "MSP"
    console.log('addContractListener:' + respName);
    const respListener = async (event) => {
      if (event.eventName === respName) {
          const details = JSON.parse(event.payload.toString('utf8'));
          console.log('************************ RespEvent *******************************************************');
          console.log('details: %j', details);
          console.log('************************ End RespEvent ************************************');
          console.log(`submit: read_response ${"Org" + org}`);
          const tx = contract.createTransaction('read_response');
          tx.setEndorsingPeers(myendorsers);
          tx.submit(details.categoryName, details.subjectName).then(()=>{
            console.log('read_response submited: %j', details);
          }).catch((err) => {
            if (err.responses[0].response.message.indexOf("Access already granted") == -1) {
              console.error('read_response error: %j error %j', details, err);
              respListener(event);
            }
          });
        }
    };
    const respListenerPromise = contract.addContractListener(respListener);

    Promise.all([reqListenerPromise, respListenerPromise]).then(()=>{
      for (let endorser of myendorsers) {
        if (!endorser.connected && !endorser.service){
          try {
            console.log("Connecting endorser %s",endorser.name);
            endorser.connect();
          } catch (err) {
            console.error(err);
          }
        }
      }
      for (let committer of channel.getCommitters()) {
        if (!committer.connected && !committer.service) {
          try {
            console.log("Connecting committer %s", committer.name);
            committer.connect();
          } catch (err) {
            console.error(err);
          }
        }
      }
      console.log('Server started.');
    });
    // Disconnect from the gateway.
    await gateway.disconnect();
  } catch (error) {
    console.error(`Failed run listener: ${error}`);
  }
}

getEvents();
