package main

import (
	"encoding/pem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	logging "github.com/op/go-logging"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

var log = logging.MustGetLogger("chinese_wall")
var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

var StateDB string
var PrivateDB string

const PublicKeyList = "PublicKeyList"
const PublicKeyIndex = "pk~name"
const PrivateDataList = "PrivateDataList"
const PrivateKeyEntry = "privateKey"
const ReqEventPrefix = "ReqEvent"
const RespEventPrefix = "RespEvent"

// My unique org identifier
var CORE_PEER_LOCALMSPID string

// Response types that are recognized by this chaincode
const (
	GRANT int = iota
	REVOKE
)

// Transaction types that are recognized by this chaincode
const (
	DATA = "DATA"
	REQ = "REQ"
	RESP = "RESP"
	PUCAT = "PUCAT"
	PRCAT = "PRCAT"
	PK = "PK"
)

type PKTransaction struct {
	ObjectType 	string	`json:"docType"`
	Org     		string	`json:"org"`
	PublicKey  	[]byte	`json:"publicKey"`
}

type ReqTransaction struct {
	ObjectType	string	`json:"docType"`
	Category		string	`json:"categoryName"`
	Subject			string	`json:"subjectName"`
	Org					string	`json:"org"`
}

type RespTransaction struct {
	ObjectType	string	`json:"docType"`
	Category		string	`json:"categoryName"`
	Subject			string	`json:"subjectName"`
	Org     		string	`json:"org"`
	Response		int			`json:"response"`
	EncKey			[]byte	`json:"key"`
	EncNonce		[]byte	`json:"nonce"`
	Creator			string	`json:"creator"`
	Timestamp		int64	  `json:"timestamp"`
	// EncReason		string	`json:"reason"`
}

type Event struct {
	Category		string	`json:"categoryName"`
	Subject			string	`json:"subjectName"`
	Org					string	`json:"org"`
	Creator			string	`json:"creator"`
}

// Category to describe user defined categories in private db
type PrivateCategory struct {
	ObjectType	string										`json:"docType"`
	Name				string										`json:"categoryName"`
	Subjects		map[string]PrivateSubject	`json:"subjects"`
	Creator			string										`json:"creator"`
}

// Subject to describe data specific subject for a certain category in private db
type PrivateSubject struct {
	Name       string							`json:"subjectName"`
	Data       []string						`json:"data"`
	AccessList []string						`json:"accessList"`
	Creator    string							`json:"creator"`
	Keys       map[string][]byte	`json:"keys"`
	Nonces     map[string][]byte	`json:"nonces"`
}

// Category to describe user defined categories on blockchain
type PublicCategory struct {
	ObjectType string                   `json:"docType"`
	Name       string                   `json:"name"`
	Subjects   map[string]PublicSubject `json:"subjects"`
	Creator    string                   `json:"creator"`
}

// Subject to describe data specific subject for a certain category on blockchain
type PublicSubject struct {
	Name			string              `json:"subjectName"`
	EncData		map[string][][]byte	`json:"encData"`
	Creator		string             	`json:"creator"`
}

type PrivateData struct {
	ObjectType	string    `json:"docType"`
	Category		string		`json:"categoryName"`
	Subject 		string		`json:"subjectName"`
	Data      	[]string	`json:"data"`
	Key					[]byte		`json:"key"`
	Nonce     	[]byte		`json:"nonce"`
}

type ChineseWall struct {
}

func (t *ChineseWall) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func (t *ChineseWall) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()
	log.Debugf("Invoke: function %s args %v", function, args)

	// Handle different functions
	switch function {
	case "init_pub":
		//initialize public key
		return t.init_pub(stub, args)
	case "init_priv":
		//initialize private key
		return t.init_priv(stub, args)
	case "get_pub":
		//get public key
		return t.get_pub(stub, args)
	case "get_priv":
		//get private key
		return t.get_priv(stub, args)
	case "new_category":
		//create a new category
		return t.new_category(stub, args)
	case "new_subject":
		//create a new subject
		return t.new_subject(stub, args)
	case "new_data":
		//add data for a subject
		return t.new_data(stub, args)
	case "request_subject":
		//request access to data from a subject
		return t.request_subject(stub, args)
	case "respond_request":
		//respond to a request for access to data
		return t.respond_request(stub, args)
	case "read_response":
		//read response to request for access to data
		return t.read_response(stub, args)
	case "list_categories_pub":
		//list all public categories
		return t.list_categories_pub(stub, args)
	case "list_categories_priv":
		//list all private categories
		return t.list_categories_priv(stub, args)
	case "list_my_categories":
		//list all categories created by this org
		return t.list_my_categories(stub, args)
	case "list_subjects_pub":
		//list all public subjects in a category
		return t.list_subjects_pub(stub, args)
	case "list_subjects_priv":
		//list all private subjects in a category
		return t.list_subjects_priv(stub, args)
	case "list_my_subjects":
		//list all subject created by this org for a category
		return t.list_my_subjects(stub, args)
	case "list_data_priv":
		//list all private data for a subject in a category
		return t.list_data_priv(stub, args)
	case "list_my_data":
		//list all data created by this org for a subject and category
		return t.list_my_data(stub, args)
	default:
		//error
		log.Errorf("Invoke could not find function: function %s", function)
		return shim.Error("Invoke could not find function: function " + function)
	}
}

func (t *ChineseWall) init_pub(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		log.Errorf("Expected 2 arguments: len(args) %v", len(args))
		return shim.Error("Expecting category name, public key as arguments.")
	}
	if len(args[0]) <= 0 {
		log.Errorf("Organization Name must be a non-empty string.: len(args[0]) %v", len(args[0]))
		return shim.Error("Organization Name must be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		log.Errorf("Public Key must be a non-empty string.: len(args[1]) %v", len(args[1]))
		return shim.Error("Public Key must be a non-empty string.")
	}

	orgName := args[0]
	pubBytes64 := args[1]

	pubBytes, err := base64.StdEncoding.DecodeString(pubBytes64)
	if err != nil {
		log.Errorf("Error decoding base64 public key: err %v", err)
		return shim.Error("Error decoding base64 public key: err " + err.Error())
	}
	log.Debug("Decoded base64 public key input.")

	log.Debug("Parsed arguments.")

	pkTransaction := PKTransaction{
		ObjectType: PK,
		Org:     orgName,
		PublicKey:  []byte(pubBytes),
	}

	pkTransactionAsBytes, err := json.Marshal(pkTransaction)
	if err != nil {
		log.Errorf("Error marshaling PKTransaction struct to json: err %v", err)
		return shim.Error("Error marshaling PKTransaction struct to json: err " + err.Error())
	}
	log.Debug("Marshaled public key to PKTransaction struct to json")

	err = stub.PutState(orgName, pkTransactionAsBytes)
	if err != nil {
		log.Errorf("Error storing PKTransaction struct in blockchain: key %s err %v", orgName, err)
		return shim.Error("Error storing public key in blockchain: err " + err.Error())
	}
	log.Debug("Stored pkTransaction in blockchain")
	return shim.Success(nil)

}

func (t *ChineseWall) init_priv(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 0 {
		log.Errorf("Expected 0 argument: len(args) %v", len(args))
		return shim.Error("Expecting data as transient input.")
	}
	err := ioutil.WriteFile("/tmp/data", []byte(""), 0644)
	if err != nil {
		log.Errorf("Error creating file: err %v",err)
		return shim.Error("Error creating file: err " + err.Error())
	}
	transMap, err := stub.GetTransient()
	if err != nil {
		log.Errorf("Error getting transient inputs: err %v",err)
		return shim.Error("Error getting transient inputs: err " + err.Error())
	}
	privBytes, ok := transMap["private_key"]

	if !ok {
		log.Error("Private Key not in transient inputs with key \"private_key\"")
		return shim.Error("Private Key not in transient inputs with key \"private_key\"")
	}

	if len(privBytes) <= 0 {
		log.Errorf("Private Key must be a non-empty string.: len(privBytes) %v", len(privBytes))
		return shim.Error("Private key must be a non-empty string.")
	}

	log.Debug("Parsed arguments.")

	err = stub.PutPrivateData(PrivateDB, PrivateKeyEntry, privBytes)
	if err != nil {
		log.Errorf("Error storing public key encryption secret key in private db: key %s err %v", PrivateKeyEntry, err)
		return shim.Error("Error storing public key encryption secret key in private db: err " + err.Error())
	}
	log.Debug("Stored public key encryption secret key in private db.")

	return shim.Success(nil)

}

func (t *ChineseWall) get_pub(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		log.Errorf("Expected 1 argument: len(args) %v", len(args))
		return shim.Error("Expecting organization name as argument.")
	}
	if len(args[0]) <= 0 {
		log.Errorf("Organization Name must be a non-empty string.: len(args[0]) %v", len(args[0]))
		return shim.Error("Organization Name must be a non-empty string.")
	}

	orgName := args[0]
	log.Debug("Parsed arguments.")

	publicKeyTxAsBytes, err := stub.GetState(orgName)
	if err != nil {
		log.Errorf("Public key could not be found: org %s err %v", orgName, err)
		return shim.Error("Public key could not be found: org " + orgName + " err " + err.Error())
	}
	log.Debug("Public key found")

	return shim.Success(publicKeyTxAsBytes)
}

func (t *ChineseWall) get_priv(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 0 {
		log.Errorf("Expected 0 arguments: len(args) %v", len(args))
		return shim.Error("Expecting 0 arguments.")
	}

	privateKeyAsBytes, err := stub.GetPrivateData(PrivateDB, PrivateKeyEntry)
	if err != nil {
		log.Errorf("Data could not be found: err %v", err)
		return shim.Error("Data could not be found: err " + err.Error())
	} else if privateKeyAsBytes == nil {
		log.Error("Private key not found")
		return shim.Error("Private key not found")
	}
	log.Debug("Private key found.")

	return shim.Success(privateKeyAsBytes)
}

func (t *ChineseWall) new_category(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		log.Errorf("Expected 1 argument: len(args) %v", len(args))
		return shim.Error("Expecting category name as argument.")
	}
	if len(args[0]) <= 0 {
		log.Errorf("Category Name must be a non-empty string.: len(args[0]) %v", len(args[0]))
		return shim.Error("Category Name must be a non-empty string.")
	}
	categoryName := args[0]

	log.Debug("Parsed arguments.")

	_, err := getPrivateCategory(stub, categoryName)
	if err == nil {
		log.Errorf("Category already exists: categoryName %s", categoryName)
		return shim.Error("Category already exists: categoryName " + categoryName)
	}
	log.Debug("Category not found. Creating.")

	privateCategory := &PrivateCategory{
		ObjectType: PRCAT,
		Name:     categoryName,
		Subjects: map[string]PrivateSubject{},
		Creator:  CORE_PEER_LOCALMSPID,
	}

	privateCategoryJSONasBytes, err := json.Marshal(privateCategory)
	if err != nil {
		log.Errorf("Error marshaling privateCategory struct to json: err %v", err)
		return shim.Error("Error marshaling privateCategory struct to json: err " + err.Error())
	}
	log.Debug("Marshaled privateCategory struct to json")

	err = stub.PutPrivateData(StateDB, categoryName, privateCategoryJSONasBytes)
	if err != nil {
		log.Errorf("Error storing privateCategory in private db: key %s err %v", categoryName, err)
		return shim.Error("Error storing privateCategory in private db: err " + err.Error())
	}
	log.Debugf("Stored privateCategory to private db %s", StateDB)

	publicCategory := &PublicCategory{
		ObjectType: PUCAT,
		Name:       categoryName,
		Subjects:   map[string]PublicSubject{},
		Creator:    CORE_PEER_LOCALMSPID,
	}

	publicCategoryJSONasBytes, err := json.Marshal(publicCategory)
	if err != nil {
		log.Errorf("Error marshaling publicCategory struct to json: err %v", err)
		return shim.Error("Error marshaling publicCategory struct to json: err " + err.Error())
	}
	log.Debug("Marshaled publicCategory struct to json")

	err = stub.PutState(categoryName, publicCategoryJSONasBytes)
	if err != nil {
		log.Errorf("Error storing PublicCategory struct in blockchain: key %s err %v", categoryName, err)
		return shim.Error("Error storing public category in blockchain: err " + err.Error())
	}
	log.Debug("Stored publicCategory in blockchain")

	return shim.Success(nil)
}

func (t *ChineseWall) new_category_multi(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) >= 2 {
		log.Errorf("Expected 2+ argument: len(args) %v", len(args))
		return shim.Error("Expecting category name, organization names as argument.")
	}
	if len(args[0]) <= 0 {
		log.Errorf("Category Name must be a non-empty string.: len(args[0]) %v", len(args[0]))
		return shim.Error("Category Name must be a non-empty string.")
	}
	categoryName := args[0]

	log.Debug("Parsed arguments.")

	_, err := getPrivateCategory(stub, categoryName)
	if err == nil {
		log.Errorf("Category already exists: categoryName %s", categoryName)
		return shim.Error("Category already exists: categoryName " + categoryName)
	}
	log.Debug("Category not found. Creating.")

	privateCategory := &PrivateCategory{
		ObjectType: PRCAT,
		Name:     categoryName,
		Subjects: map[string]PrivateSubject{},
		Creator:  CORE_PEER_LOCALMSPID,
	}

	privateCategoryJSONasBytes, err := json.Marshal(privateCategory)
	if err != nil {
		log.Errorf("Error marshaling privateCategory struct to json: err %v", err)
		return shim.Error("Error marshaling privateCategory struct to json: err " + err.Error())
	}
	log.Debug("Marshaled privateCategory struct to json")

	err = stub.PutPrivateData(StateDB, categoryName, privateCategoryJSONasBytes)
	if err != nil {
		log.Errorf("Error storing privateCategory in private db: key %s err %v", categoryName, err)
		return shim.Error("Error storing privateCategory in private db: err " + err.Error())
	}
	log.Debugf("Stored privateCategory to private db %s", StateDB)

	publicCategory := &PublicCategory{
		ObjectType: PUCAT,
		Name:       categoryName,
		Subjects:   map[string]PublicSubject{},
		Creator:    CORE_PEER_LOCALMSPID,
	}

	publicCategoryJSONasBytes, err := json.Marshal(publicCategory)
	if err != nil {
		log.Errorf("Error marshaling publicCategory struct to json: err %v", err)
		return shim.Error("Error marshaling publicCategory struct to json: err " + err.Error())
	}
	log.Debug("Marshaled publicCategory struct to json")

	err = stub.PutState(categoryName, publicCategoryJSONasBytes)
	if err != nil {
		log.Errorf("Error storing PublicCategory struct in blockchain: key %s err %v", categoryName, err)
		return shim.Error("Error storing public category in blockchain: err " + err.Error())
	}
	log.Debug("Stored publicCategory in blockchain")

	return shim.Success(nil)
}

func (t *ChineseWall) new_subject(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		log.Errorf("Expected 2 arguments: len(args) %v", len(args))
		return shim.Error("Expecting category name, subject name as arguments.")
	}
	if len(args[0]) <= 0 {
		log.Errorf("Category name must be a non-empty string.: len(args[0]) %v", len(args[0]))
		return shim.Error("Category name must be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		log.Errorf("Subject name must be a non-empty string.: len(args[1]) %v", len(args[1]))
		return shim.Error("Subject name must be a non-empty string.")
	}

	categoryName := args[0]
	subjectName := args[1]

	log.Debug("Parsed arguments.")

	privateCategory, err := getPrivateCategory(stub, categoryName)
	if err != nil {
		log.Errorf("getPrivateCategory %v", err)
		return shim.Error(err.Error())
	}
	log.Debug("Private category found.")

	_, ok := privateCategory.Subjects[subjectName]
	if ok {
		log.Errorf("Subject already exists: categoryName %s subjectName %s", categoryName, subjectName)
		return shim.Error("Subject already exists: categoryName " + categoryName + " subjectName " + subjectName)
	}
	log.Debug("Private subject not found. Creating.")

	privateSubject := PrivateSubject{
		Name:       subjectName,
		Data:       []string{},
		AccessList: []string{},
		Creator:    CORE_PEER_LOCALMSPID,
		Keys:       map[string][]byte{},
		Nonces:     map[string][]byte{},
	}

	orgs, err := getOrgList(stub)
	if err != nil {
		log.Errorf("getOrgList %v", err)
		return shim.Error(err.Error())
	}
	log.Debugf("Org list found %v.", orgs)

	for _, org := range orgs {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			log.Errorf("Error generating private key: err %v", err)
			return shim.Error("Error generating private key: err" + err.Error())
		}

		nonce := make([]byte, 12)
		_, err = rand.Read(nonce)
		if err != nil {
			log.Errorf("Error generating random nonce: err %v", err)
			return shim.Error("Error generating random nonce: err" + err.Error())
		}

		privateSubject.Keys[org] = key
		privateSubject.Nonces[org] = nonce
	}
	log.Debug("Org keys generated.")

	privateCategory.Subjects[subjectName] = privateSubject

	privateCategoryJSONasBytes, err := json.Marshal(privateCategory)
	if err != nil {
		log.Errorf("Error marshaling PrivateCategory struct to json: err %v", err)
		return shim.Error("Error marshaling PrivateCategory struct to json: err " + err.Error())
	}
	log.Debug("Marshaled privateCategory struct to json")
	err = stub.PutPrivateData(StateDB, categoryName, privateCategoryJSONasBytes)
	if err != nil {
		log.Errorf("Error storing privateCategory in private db: key %s err %v", categoryName, err)
		return shim.Error("Error storing privateCategory in private db: err " + err.Error())
	}
	log.Debugf("Stored privateCategory to private db %s", StateDB)

	publicCategory, err := getPublicCategory(stub, categoryName)
	if err != nil {
		log.Debugf("getPublicCategory: err %v", err)
		return shim.Error(err.Error())
	}
	log.Debug("Public category found.")

	_, ok = publicCategory.Subjects[subjectName]
	if ok {
		log.Errorf("Subject already exists: categoryName %s subjectName %v", categoryName, subjectName)
		return shim.Error("Subject already exists: categoryName " + categoryName + " subjectName " + subjectName)
	}
	log.Debug("Public subject not found. Creating.")

	publicSubject := PublicSubject{
		Name:       subjectName,
		EncData:    map[string][][]byte{},
		Creator:    CORE_PEER_LOCALMSPID,
		// EncKeys:    map[string][]byte{},
		// EncNonces:  map[string][]byte{},
	}

	// for i, org := range orgs {
	// 	key := privateSubject.Keys[org]
	// 	nonce := privateSubject.Nonces[org]
	// 	pk := pks[i]
	// 	encKey, err := puEncrypt(key, pk)
	// 	if err != nil {
	// 		log.Errorf("Error encrypting keys: err %v", err)
	// 		return shim.Error("Error encrypting data: err " + err.Error())
	// 	}
	// 	encNonce, err := puEncrypt(nonce, pk)
	// 	if err != nil {
	// 		log.Errorf("Error encrypting keys: err %v", err)
	// 		return shim.Error("Error encrypting data: err " + err.Error())
	// 	}
	// }
	// log.Debug("Keys encrypted.")


	publicCategory.Subjects[subjectName] = publicSubject

	publicCategoryJSONasBytes, err := json.Marshal(publicCategory)
	if err != nil {
		log.Errorf("Error marshaling PublicCategory struct to json: err %v", err)
		return shim.Error("Error marshaling PublicCategory struct to json: err " + err.Error())
	}
	log.Debug("Marshaled publicCategory struct to json")

	err = stub.PutState(categoryName, publicCategoryJSONasBytes)
	if err != nil {
		log.Errorf("Error storing PublicCategory struct in blockchain: key %s err %v", categoryName, err)
		return shim.Error("Error storing public category in blockchain: err " + err.Error())
	}
	log.Debug("Stored publicCategory in blockchain")

	return shim.Success(nil)
}

func (t *ChineseWall) new_data(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		log.Errorf("Expected 2 arguments: len(args) %v", len(args))
		return shim.Error("Expecting category name, subject name as arguments.")
	}
	if len(args[0]) <= 0 {
		log.Errorf("Category name must be a non-empty string.: len(args[0]) %v", len(args[0]))
		return shim.Error("Category name to be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		log.Errorf("Subject name must be a non-empty string.: len(args[1]) %v", len(args[1]))
		return shim.Error("Subject name must be a non-empty string.")
	}
	transMap, err := stub.GetTransient()
	if err != nil {
		log.Errorf("Error getting transient input: err %v",err)
		return shim.Error("Error getting transient input: err " + err.Error())
	}
	categoryName := args[0]
	subjectName := args[1]
	data, ok := transMap["data"]
	if !ok {
		log.Error("Data not in transient input with key \"data\"")
		return shim.Error("Data not in transient input with key \"data\"")
	}

	log.Debug("Parsed arguments.")

	privateCategory, err := getPrivateCategory(stub, categoryName)
	if err != nil {
		log.Errorf("getPrivateCategory: %v", err)
		return shim.Error(err.Error())
	}
	log.Debug("Private category found.")

	privateSubject, ok := privateCategory.Subjects[subjectName]
	if !ok {
		log.Debug("Private subject not found: categoryName %s subjectName %s", categoryName, subjectName)
		return shim.Error("Subject not found: categoryName " + categoryName + " subjectName " + subjectName)
	}
	log.Debug("Private subject found.")

	publicCategory, err := getPublicCategory(stub, categoryName)
	if err != nil {
		log.Debugf("getPublicCategory: err %v", err)
		return shim.Error(err.Error())
	}
	log.Debug("Public category found.")

	publicSubject, ok := publicCategory.Subjects[subjectName]
	if !ok {
		log.Debug("Public subject not found: categoryName %s subjectName %s", categoryName, subjectName)
		return shim.Error("Subject not found: categoryName " + categoryName + " subjectName " + subjectName)
	}
	log.Debug("Public subject found.")

	for org, key := range privateSubject.Keys {
		nonce := privateSubject.Nonces[org]
		encData, err := prEncrypt([]byte(data), key, nonce)
		if err != nil {
			log.Errorf("Error encrypting data: err %v", err)
			return shim.Error("Error encrypting data: err " + err.Error())
		}
		publicSubject.EncData[org] = append(publicSubject.EncData[org], encData)
	}
	log.Debug("Data encrypted.")

	privateSubject.Data = append(privateSubject.Data, string(data))
	privateCategory.Subjects[subjectName] = privateSubject

	privateCategoryJSONasBytes, err := json.Marshal(privateCategory)
	if err != nil {
		log.Errorf("Error marshaling PrivateCategory struct to json: err %v", err)
		return shim.Error("Error marshaling PrivateCategory struct to json: err " + err.Error())
	}
	log.Debug("Marshaled privateCategory struct to json")

	err = stub.PutPrivateData(StateDB, categoryName, privateCategoryJSONasBytes)
	if err != nil {
		log.Errorf("Error storing privateCategory in private db: key %s err %v", categoryName, err)
		return shim.Error("Error storing privateCategory in private db: err " + err.Error())
	}
	log.Debugf("Stored privateCategory to private db %s", StateDB)

	publicCategory.Subjects[subjectName] = publicSubject

	publicCategoryJSONasBytes, err := json.Marshal(publicCategory)
	if err != nil {
		log.Errorf("Error marshaling PublicCategory struct to json: err %v", err)
		return shim.Error("Error marshaling PublicCategory struct to json: err " + err.Error())
	}
	log.Debug("Marshaled publicCategory struct to json")

	err = stub.PutState(categoryName, publicCategoryJSONasBytes)
	if err != nil {
		log.Errorf("Error storing PublicCategory struct in blockchain: key %s err %v", categoryName, err)
		return shim.Error("Error storing public category in blockchain: err " + err.Error())
	}
	log.Debug("Stored publicCategory in blockchain")

	return shim.Success(nil)
}

func (t *ChineseWall) request_subject(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		log.Errorf("Expected 2 arguments: len(args) %v", len(args))
		return shim.Error("Expecting category name, subject name as arguments.")
	}
	if len(args[0]) <= 0 {
		return shim.Error("Category name must be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		return shim.Error("Subject name must be a non-empty string.")
	}

	categoryName := args[0]
	subjectName := args[1]

	now := time.Now()
	nsec := now.UnixNano()
	data := fmt.Sprintf("%s,%s,request_subject,%v",categoryName,subjectName,nsec)
	log.Infof("Eval: %s",data)
	file, err := os.OpenFile("/tmp/data", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Errorf("Error writing timestamp: err %v", err)
		return shim.Error("Error writing timestamp: err" + err.Error())
	}
	defer file.Close()
  if _, err := file.WriteString(data + "\n"); err != nil {
		log.Errorf("Error writing timestamp: err %v", err)
		return shim.Error("Error writing timestamp: err" + err.Error())
  }

	log.Debug("Parsed arguments.")

	privateCategory, err := getPrivateCategory(stub, categoryName)
	if err == nil {
		_, ok := privateCategory.Subjects[subjectName]
		if ok {
			log.Errorf("Already have access to subject in category: categoryName %s subjectName %s " + subjectName + "  " + categoryName)
			return shim.Error("Already have access to subject in category: categoryName " + categoryName + " subjectName " + subjectName)
		}
	}
	log.Debug("Access not granted yet.")

	publicCategory, err := getPublicCategory(stub, categoryName)
	if err != nil {
		log.Debugf("getPublicCategory: err %v",err)
		return shim.Error(err.Error())
	}
	log.Debug("Public category found.")
	org := publicCategory.Creator

	_, ok := publicCategory.Subjects[subjectName]
	if !ok {
		log.Debug("Subject not found: categoryName %s subjectName %s", categoryName, subjectName)
		return shim.Error("Subject not found: categoryName " + categoryName + " subjectName " + subjectName)
	}
	log.Debug("Public subject found.")

	reqTransaction := &ReqTransaction{
		ObjectType: REQ,
		Category: 	categoryName,
		Subject: 		subjectName,
		Org: 	 			CORE_PEER_LOCALMSPID,
	}

	reqTrnasactionJSONasBytes, err := json.Marshal(reqTransaction)
	if err != nil {
		log.Errorf("Error marshaling ReqTransaction struct to json: err %v", err)
		return shim.Error("Error marshaling ReqTransaction struct to json: err" + err.Error())
	}
	log.Debug("Marshaled ReqTransaction struct to json")

	reqEvent := &Event{
		Category: 	categoryName,
		Subject: 		subjectName,
		Org:				org,
		Creator:    CORE_PEER_LOCALMSPID,
	}
	eventJSONasBytes, err := json.Marshal(reqEvent)
	if err != nil {
		log.Errorf("Error marshaling Event struct to json: err %v", err)
		return shim.Error("Error marshaling Event struct to json: err " + err.Error())
	}
	log.Debug("Marshaled Event struct to json.")


	key := REQ + "-" + categoryName + "-" + subjectName + "-" + CORE_PEER_LOCALMSPID
	err = stub.PutState(key, reqTrnasactionJSONasBytes)
	if err != nil {
		log.Errorf("Error storing ReqTransaction struct in blockchain: key %s err %v", key, err)
		return shim.Error("Error storing access request in blockchain: err " + err.Error())
	}
	log.Debug("Stored reqTransaction in blockchain")

	err = stub.SetEvent(ReqEventPrefix + org, eventJSONasBytes)
	if err != nil {
		log.Errorf("Error setting ReqEvent in blockchain: key %s err %v",ReqEventPrefix+org, err)
		return shim.Error("Error setting ReqEvent in blockchain: err " + err.Error())
	}
	log.Debug("Stored reqEvent in blockchain.")
	return shim.Success(nil)
}

func (t *ChineseWall) respond_request(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 3 {
		log.Errorf("Expected 3 arguments: len(args) %v", len(args))
		return shim.Error("Expecting category name, subject name, organization id as arguments.")
	}
	if len(args[0]) <= 0 {
		return shim.Error("Category name must be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		return shim.Error("Subject name must be a non-empty string.")
	}
	if len(args[2]) <= 0 {
		return shim.Error("Org must be a non-empty string.")
	}

	categoryName := args[0]
	subjectName := args[1]
	org := args[2]

	log.Debug("Parsed arguments.")

	privateCategory, err := getPrivateCategory(stub, categoryName)
	if err != nil {
		log.Warningf("Revoking getPrivateCategory: err %v", err)
		return sendRevoke(stub, categoryName, subjectName, org)
	}
	log.Debug("Private category found.")

	for name, value := range privateCategory.Subjects {
		if contains(value.AccessList, org) && name != subjectName {
			log.Warningf("Org already has access to subject in category: categoryName %s subjectName %s org %s", categoryName, subjectName, org)
			return sendRevoke(stub, categoryName, subjectName, org)
		}
	}
	log.Debug("Org not in any access list for category.")
	log.Debug("Access not granted yet.")

	privateSubject, ok := privateCategory.Subjects[subjectName]
	if !ok {
		log.Warningf("Private subject for category not found: categoryName %s subjectName %s", categoryName, subjectName)
		return sendRevoke(stub, categoryName, subjectName, org)
	}
	log.Debug("Private subject found.")

	privateSubject.AccessList = append(privateSubject.AccessList, org)
	log.Debug("Add org to AccessList.")

	privateCategory.Subjects[subjectName] = privateSubject
	privateCategoryJSONasBytes, err := json.Marshal(privateCategory)
	if err != nil {
		log.Errorf("Error marshaling PrivateCategory struct to json: err %v", err)
		return shim.Error("Error marshaling PrivateCategory struct to json: err " + err.Error())
	}
	log.Debug("Marshaled PrivateCategory struct to json")

	err = stub.PutPrivateData(StateDB, categoryName, privateCategoryJSONasBytes)
	if err != nil {
		log.Errorf("Error storing privateCategory in private db: key %s err %v", categoryName, err)
		return shim.Error("Error storing privateCategory in private db: err " + err.Error())
	}
	log.Debugf("Stored privateCategory to private db %s", StateDB)

	publicKey, err := getOrgPublicKey(stub, org)
	if err != nil {
		log.Warningf("Error getOrgPublicKey: org %s err %v", org, err)
		return sendRevoke(stub, categoryName, subjectName, org)
	}
	log.Debug("Org public key found.")

	encKey, err := puEncrypt(privateCategory.Subjects[subjectName].Keys[org], publicKey)
	if err != nil {
		log.Warningf("Public Key encryption could not be done for org key: org %s err %v ", org, err)
		return sendRevoke(stub, categoryName, subjectName, org)
	}
	log.Debug("Encrypted key.")

	encNonce, err := puEncrypt(privateCategory.Subjects[subjectName].Nonces[org], publicKey)
	if err != nil {
		log.Warningf("Public Key encryption could not be done for org nonce: org %s err %v ", org, err)
		return sendRevoke(stub, categoryName, subjectName, org)
	}
	log.Debug("Encrypted nonce.")


	timestamp,err := stub.GetTxTimestamp()
	if err != nil {
		log.Errorf("Error getting transaction timestamp: err %v", err)
		return shim.Error("Error getting transaction timestamp: err " + err.Error())
	}
	log.Debug("Got transaction timestamp.")


	grantResp := &RespTransaction{
		ObjectType: RESP,
		Category: 	categoryName,
		Subject: 		subjectName,
		Org:				org,
		Response:   GRANT,
		EncKey:			encKey,
		EncNonce: 	encNonce,
		Creator: 		CORE_PEER_LOCALMSPID,
		Timestamp:  timestamp.GetSeconds(),
	}

	grantRespJSONasBytes, err := json.Marshal(grantResp)
	if err != nil {
		log.Errorf("Error marshaling RespTransaction struct to json: err %v", err)
		return shim.Error("Error marshaling RespTransaction struct to json: err " + err.Error())
	}
	log.Debug("Marshaled RespTransaction struct to json.")

	respEvent := &Event{
		Category: 	categoryName,
		Subject: 		subjectName,
		Org:				org,
		Creator:    CORE_PEER_LOCALMSPID,
	}
	eventJSONasBytes, err := json.Marshal(respEvent)

	if err != nil {
		log.Errorf("Error marshaling Event struct to json: err %v", err)
		return shim.Error("Error marshaling Event struct to json: err " + err.Error())
	}
	log.Debug("Marshaled Event struct to json.")

	key := RESP + "-" + categoryName + "-" + subjectName + "-" + CORE_PEER_LOCALMSPID + "-to-" + org + strconv.Itoa(int(timestamp.GetSeconds()))
	err = stub.PutState(key, grantRespJSONasBytes)
	if err != nil {
		log.Errorf("Error storing RespTransaction struct in blockchain: key %s err %v", key, err)
		return shim.Error("Error storing access response in blockchain: err " + err.Error())
	}

	log.Debug("Stored grantResp in blockchain.")

	err = stub.SetEvent(RespEventPrefix + org, eventJSONasBytes)
	if err != nil {
		log.Errorf("Error setting RespEvent in blockchain: key %s err %v",RespEventPrefix+org, err)
		return shim.Error("Error setting RespEvent in blockchain: err " + err.Error())
	}

	log.Debug("Stored respEvent in blockchain.")

	return shim.Success([]byte("Granted: categoryName " + categoryName + " subjectName " + subjectName + " org " + org))
}

func (t *ChineseWall) read_response(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		log.Errorf("Expected 2 arguments: len(args) %v", len(args))
		return shim.Error("Expecting category name, subject name as arguments.")
	}
	if len(args[0]) <= 0 {
		return shim.Error("Category name must be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		return shim.Error("Subject name must be a non-empty string.")
	}

	categoryName := args[0]
	subjectName := args[1]

	log.Debug("Parsed arguments.")

	_, err := getPrivateData(stub, categoryName, subjectName)
	if err == nil {
		log.Debugf("Access already granted for subject in the category: categoryName %s subjectName %s ", categoryName, subjectName)
		return shim.Error("Access already granted for subject in the category: categoryName " + categoryName + " subjectName " + subjectName)
	}
	log.Debug("Private data not found yet.")

	privateCategory, err := getPrivateCategory(stub, categoryName)
	if err == nil {
		_, ok := privateCategory.Subjects[subjectName]
		if ok {
			log.Errorf("Subject already exists: categoryName %s subjectName %v", categoryName, subjectName)
			return shim.Error("Subject already exists: categoryName " + categoryName + " subjectName " + subjectName)
		}
	}
	log.Debug("Private category not found yet.")

	privateKey, err := getPrivateKey(stub)
	if err != nil {
		log.Errorf("getPrivateKey %v", err)
		return shim.Error(err.Error())
	}
	log.Debug("Private key found.")

	publicCategory, err := getPublicCategory(stub, categoryName)
	if err != nil {
		log.Errorf("getPublicCategory %v", err)
		return shim.Error(err.Error())
	}
	log.Debug("Public category found.")

	publicSubject, ok := publicCategory.Subjects[subjectName]
	if !ok {
		log.Errorf("Subject not found: categoryName %s subjectName %s", categoryName, subjectName)
		return shim.Error("Subject not found: categoryName " + categoryName + " subjectName " + subjectName)
	}
	log.Debug("Public subject found.")

	org := publicSubject.Creator

	response, err := getResponse(stub, categoryName, subjectName, org)
	if err != nil {
		log.Errorf("getResponse %v", getResponse)
		return shim.Error(err.Error())
	}
	if response.Response != GRANT {
		log.Warningf("Response: request denied: response %v", response)
		return shim.Success([]byte("Response: request denied"))
	}

	encKey := response.EncKey
	if encKey == nil || len(encKey) == 0 {
		log.Errorf("Encrypted private key not found: encKey %s", encKey)
		return shim.Error("Encrypted private key not found" )
	}
	log.Debug("Encrypted key found.")

	encNonce := response.EncNonce
	if encNonce == nil || len(encNonce) ==0  {
		log.Errorf("Encrypted nonce not found: categoryName %s subjectName %s org %s", categoryName, subjectName, CORE_PEER_LOCALMSPID)
		return shim.Error("Encrypted nonce not found: categoryName " + categoryName + " subjectName " + subjectName + " org " + CORE_PEER_LOCALMSPID)
	}
	log.Debug("Encrypted nonce found.")

	key, err := puDecrypt(encKey, privateKey)
	if err != nil {
		log.Errorf("Public Key decryption could not be done for encyrpted key: err %v", err)
		return shim.Error("Public Key decryption could not be done for encyrpted key: err " + err.Error())
	}
	log.Debug("Key decrypted.")

	nonce, err := puDecrypt(encNonce, privateKey)
	if err != nil {
		log.Errorf("Public Key decryption could not be done for encyrpted nonce: err %v", err)
		return shim.Error("Public Key decryption could not be done for encyrpted nonce: err " + err.Error())
	}
	log.Debug("Nonce decrypted.")

	privData := PrivateData{
		ObjectType: DATA,
		Category: categoryName,
		Subject:	subjectName,
		Data:     []string{},
		Key: 			key,
		Nonce:		nonce,
	}

	for _, encData := range publicSubject.EncData[CORE_PEER_LOCALMSPID] {
		data, err := prDecrypt(encData, key, nonce)
		if err != nil {
			log.Errorf("Private Key decryption could not be done for data: err %v", err)
			return shim.Error("Private Key decryption could not be done for data: err " + err.Error())
		}
		privData.Data = append(privData.Data, string(data))
	}
	log.Debug("Data decrypted.")

	now := time.Now()
	nsec := now.UnixNano()
	data := fmt.Sprintf("%s,%s,read_response,%v",categoryName,subjectName,nsec)
	log.Infof("Eval: %s",data)
	file, err := os.OpenFile("/tmp/data", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Errorf("Error writing timestamp: err %v", err)
		return shim.Error("Error writing timestamp: err" + err.Error())
	}
	defer file.Close()
  if _, err := file.WriteString(data + "\n"); err != nil {
		log.Errorf("Error writing timestamp: err %v", err)
		return shim.Error("Error writing timestamp: err" + err.Error())
  }

	privateDataJSONasBytes, err := json.Marshal(privData)
	if err != nil {
		log.Errorf("Error marshaling PrivateData struct to json: err %v", err)
		return shim.Error("Error marshaling PrivateData struct to json: err " + err.Error())
	}
	log.Debug("Marshaled PrivateData struct to json.")

	err = stub.PutPrivateData(PrivateDB, categoryName + "-" + subjectName, privateDataJSONasBytes)
	if err != nil {
		log.Errorf("Error storing private data in private db: key % err %v", categoryName + "-" + subjectName, err)
		return shim.Error("Error storing private data in private db: err " + err.Error())
	}
	log.Debugf("Stored privData to private db %s", PrivateDB)


	return shim.Success(nil)
}

func (t *ChineseWall) list_categories_pub(stub shim.ChaincodeStubInterface, args []string) pb.Response  {
	if len(args) != 0 {
		log.Errorf("Expected 0 argument: len(args) %v", len(args))
		return shim.Error("Expecting no arguments.")
	}

	query := fmt.Sprintf("{\"selector\":{\"docType\":\"%s\"}}", PUCAT)
	resultsIterator, err := stub.GetQueryResult(query)
	if err != nil {
		log.Errorf("Error querying categories: err %v", err)
		return shim.Error("Error querying categories: err " + err.Error())
	}
	log.Debug("Queryed blockchain.")
	publicCategoryList := []string{}
	for resultsIterator.HasNext() {
			queryResponse, err := resultsIterator.Next()
			if err != nil {
				log.Errorf("Error iterating categories: err %v", err)
				return shim.Error("Error iterating categories: err " + err.Error())
			}
			publicCategoryList = append(publicCategoryList, queryResponse.Key)
	}
	log.Infof("Results: %v", publicCategoryList)

	return shim.Success([]byte("[" + strings.Join(publicCategoryList, ",") + "]"))
}

func (t *ChineseWall) list_categories_priv(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 0 {
		log.Errorf("Expected 0 argument: len(args) %v", len(args))
		return shim.Error("Expecting no arguments.")
	}
	query := fmt.Sprintf("{\"selector\":{\"docType\":\"%s\"}}", DATA)
	resultsIterator, err := stub.GetPrivateDataQueryResult(PrivateDB, query)
	if err != nil {
		log.Errorf("Error querying categories: err %v", err)
		return shim.Error("Error querying categories: err " + err.Error())
	}
	log.Debugf("Queryed private db %s.", PrivateDB)
	privateCategoryList := []string{}
	for resultsIterator.HasNext() {
			queryResponse, err := resultsIterator.Next()
			if err != nil {
				log.Errorf("Error iterating categories: err %v", err)
				return shim.Error("Error iterating categories: err " + err.Error())
			}
			var privateData PrivateData
			err = json.Unmarshal(queryResponse.Value, &privateData)
			if err != nil {
				log.Errorf("Error unmarshaling PrivateData json to struct: err %v", err)
				return shim.Error("Error unmarshaling PrivateData json to struct: err " + err.Error())
			}
			privateCategoryList = append(privateCategoryList, privateData.Category)
	}
	log.Infof("Results: %v", privateCategoryList)
	return shim.Success([]byte("[" + strings.Join(privateCategoryList, ",") + "]"))
}

func (t *ChineseWall) list_my_categories(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 0 {
		log.Errorf("Expected 0 argument: len(args) %v", len(args))
		return shim.Error("Expecting no arguments.")
	}
	query := fmt.Sprintf("{\"selector\":{\"docType\":\"%s\"}}", PRCAT)
	resultsIterator, err := stub.GetPrivateDataQueryResult(StateDB, query)
	if err != nil {
		log.Errorf("Error querying categories: err %v", err)
		return shim.Error("Error querying categories: err " + err.Error())
	}
	log.Debugf("Queryed private db %s.", StateDB)
	privateCategoryList := []string{}
	for resultsIterator.HasNext() {
			queryResponse, err := resultsIterator.Next()
			if err != nil {
				log.Errorf("Error iterating categories: err %v", err)
				return shim.Error("Error iterating categories: err " + err.Error())
			}
			privateCategoryList = append(privateCategoryList, queryResponse.Key)
	}
	log.Infof("Results: %v", privateCategoryList)
	return shim.Success([]byte("[" + strings.Join(privateCategoryList, ",") + "]"))
}

func (t *ChineseWall) list_subjects_pub(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		log.Errorf("Expected 1 argument: len(args) %v", len(args))
		return shim.Error("Expecting category name as argument.")
	}
	if len(args[0]) <= 0 {
		log.Errorf("Category Name must be a non-empty string.: len(args[0]) %v", len(args[0]))
		return shim.Error("Category Name must be a non-empty string.")
	}

	categoryName := args[0]

	log.Debug("Parsed arguments.")

	publicCategory, err := getPublicCategory(stub, categoryName)
	if err != nil {
		log.Errorf("getPublicCategory %v", err)
		return shim.Error(err.Error())
	}
	log.Debugf("Public category found.")
	keys := make([]string, 0, len(publicCategory.Subjects))
	for k := range publicCategory.Subjects {
			keys = append(keys, k)
	}
	log.Infof("Results: %v", keys)

	return shim.Success([]byte("[" + strings.Join(keys, ",") + "]"))
}

func (t *ChineseWall) list_subjects_priv(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		log.Errorf("Expected 1 argument: len(args) %v", len(args))
		return shim.Error("Expecting category name as argument.")
	}
	categoryName := args[0]
	log.Debug("Parsed arguments.")

	query := fmt.Sprintf("{\"selector\":{\"docType\":\"%s\", \"categoryName\":\"%s\"}}", DATA, categoryName)

	resultsIterator, err := stub.GetPrivateDataQueryResult(PrivateDB, query)
	if err != nil {
		log.Errorf("Error querying subjects: err %v", err)
		return shim.Error("Error querying subjects: err " + err.Error())
	}
	log.Debugf("Queryed private db %s.", PrivateDB)

	privateSubjectList := []string{}
	for resultsIterator.HasNext() {
			queryResponse, err := resultsIterator.Next()
			if err != nil {
				log.Errorf("Error iterating subjects: err %v", err)
				return shim.Error("Error iterating subjects: err " + err.Error())
			}
			var privateData PrivateData
			err = json.Unmarshal(queryResponse.Value, &privateData)
			if err != nil {
				log.Errorf("Error unmarshaling PrivateData json to struct: err %v", err)
				return shim.Error("Error unmarshaling PrivateData json to struct: err " + err.Error())
			}
			privateSubjectList = append(privateSubjectList, privateData.Subject)
	}

	log.Infof("Results: %v", privateSubjectList)
	return shim.Success([]byte("[" + strings.Join(privateSubjectList, ",") + "]"))
}

func (t *ChineseWall) list_my_subjects(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		log.Errorf("Expected 1 argument: len(args) %v", len(args))
		return shim.Error("Expecting category name as argument.")
	}
	if len(args[0]) <= 0 {
		return shim.Error("Category name must be a non-empty string.")
	}
	categoryName := args[0]

	log.Debug("Parsed arguments.")

	privateCategory, err := getPrivateCategory(stub, categoryName)
	if err != nil {
		log.Errorf("getPrivateCategory %v", err)
		return shim.Error(err.Error())
	}
	log.Debug("Private category found.")

	keys := make([]string, 0, len(privateCategory.Subjects))
	for k := range privateCategory.Subjects {
			keys = append(keys, k)
	}
	log.Infof("Results: %v", keys)

	return shim.Success([]byte("[" + strings.Join(keys, ",") + "]"))
}

func (t *ChineseWall) list_data_priv(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		log.Errorf("Expected 2 arguments: len(args) %v", len(args))
		return shim.Error("Expecting category name, subject name as arguments.")
	}
	if len(args[0]) <= 0 {
		return shim.Error("Category name must be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		return shim.Error("Subject name must be a non-empty string.")
	}

	categoryName := args[0]
	subjectName := args[1]

	log.Debug("Parsed arguments.")

	privateData, err := getPrivateData(stub, categoryName, subjectName)
	if err != nil {
		log.Errorf("getPrivateData %v", err)
		return shim.Error(err.Error())
	}
	log.Debug("Private data found.")

	log.Infof("Results: %v", privateData)
	return shim.Success([]byte("[" + strings.Join(privateData, ",") + "]"))
}

func (t *ChineseWall) list_my_data(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		log.Errorf("Expected 2 arguments: len(args) %v", len(args))
		return shim.Error("Expecting category name, subject name as arguments.")
	}
	if len(args[0]) <= 0 {
		return shim.Error("Category name must be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		return shim.Error("Subject name must be a non-empty string.")
	}

	categoryName := args[0]
	subjectName := args[1]

	log.Debug("Parsed arguments.")

	privateCategory, err := getPrivateCategory(stub, categoryName)
	if err != nil {
		log.Errorf("getPrivateCategory %v", err)
		return shim.Error(err.Error())
	}
	log.Debug("Private category found.")

	privateSubject, ok := privateCategory.Subjects[subjectName]
	if !ok {
		log.Errorf("Subject could not be found: categoryName %s subjectName %s err %v", categoryName, err)
		return shim.Error("Subject could not be found: categoryName " + categoryName + " subjectName " + subjectName + " err " + err.Error())
	}
	log.Debug("Private subject found.")
	log.Infof("Results: %v", privateSubject.Data)

	return shim.Success([]byte("[" + strings.Join(privateSubject.Data, ",") + "]"))
}

func getPrivateCategory(stub shim.ChaincodeStubInterface, categoryName string) (*PrivateCategory, error) {
	privateCategoryAsBytes, err := stub.GetPrivateData(StateDB, categoryName)
	if err != nil {
		log.Debugf("Category could not be found: categoryName %s err %v", categoryName, err)
		return nil,fmt.Errorf("Category could not be found: categoryName %s err %v", categoryName, err)
	} else if privateCategoryAsBytes == nil {
		log.Debugf("Category could not be found: categoryName %s", categoryName)
		return nil,fmt.Errorf("Category could not be found: categoryName %s", categoryName)
	}

	var privateCategory PrivateCategory
	err = json.Unmarshal(privateCategoryAsBytes, &privateCategory)
	if err != nil {
		log.Errorf("Error unmarshaling PrivateCategory json to struct: err %v", err)
		return nil,fmt.Errorf("Error unmarshaling PrivateCategory json to struct: err %v", err)
	}

	return &privateCategory,nil
}

func getPublicCategory(stub shim.ChaincodeStubInterface, categoryName string) (*PublicCategory, error) {
	publicCategoryAsBytes, err := stub.GetState(categoryName)
	if err != nil {
		log.Debugf("Category could not be found: categoryName %s err %v", categoryName, err)
		return nil,fmt.Errorf("Category could not be found: categoryName %s err %v", categoryName, err)
	} else if publicCategoryAsBytes == nil {
		log.Debugf("Category could not be found")
		return nil,fmt.Errorf("Category could not be found")
	}

	var publicCategory PublicCategory
	err = json.Unmarshal(publicCategoryAsBytes, &publicCategory)
	if err != nil {
		log.Errorf("Error unmarshaling PublicCategory json to struct: err %v", err)
		return nil,fmt.Errorf("Error unmarshaling PublicCategory json to struct: err %v", err)
	}
	return &publicCategory,nil
}

func getPrivateData(stub shim.ChaincodeStubInterface, categoryName string, subjectName string) ([]string, error) {
	privateDataAsBytes, err := stub.GetPrivateData(PrivateDB, categoryName + "-" + subjectName)
	if err != nil {
		log.Debugf("Data could not be found: categoryName %s subjectName %s err %v", categoryName, subjectName, err)
		return nil,fmt.Errorf("Data could not be found: categoryName %s subjectName %s err %v", categoryName, subjectName, err)
	} else if privateDataAsBytes == nil {
		log.Debugf("Data could not be found: categoryName %s subjectName %s", categoryName, subjectName)
		return nil,fmt.Errorf("Data could not be found: categoryName %s subjectName %s", categoryName, subjectName)
	}

	var privateData PrivateData
	err = json.Unmarshal(privateDataAsBytes, &privateData)
	if err != nil {
		log.Errorf("Error unmarshaling PrivateData json to struct: err %v", err)
		return nil,fmt.Errorf("Error unmarshaling PrivateData json to struct: err %v", err)
	}

	publicCategory, err := getPublicCategory(stub, categoryName)
	if err != nil {
		log.Debugf("getPublicCategory: err %v", err)
		return nil, err
	}

	publicSubject, ok := publicCategory.Subjects[subjectName]
	if !ok {
		return privateData.Data, nil
	}

	for _, encData := range publicSubject.EncData[CORE_PEER_LOCALMSPID] {
		data, err := prDecrypt(encData, privateData.Key, privateData.Nonce)
		if err != nil {
			log.Errorf("Private Key decryption could not be done for data: err %v", err)
		} else {
			if !contains(privateData.Data, string(data)) {
				privateData.Data = append(privateData.Data, string(data))
			}
		}
	}

	return privateData.Data,nil
}

func getPrivateKey(stub shim.ChaincodeStubInterface) (*rsa.PrivateKey, error) {
	privateKeyAsBytes, err := stub.GetPrivateData(PrivateDB, PrivateKeyEntry)
	if err != nil {
		log.Debugf("Private key could not be found: err %v", err)
		return nil,fmt.Errorf("Private key could not be found: err %v", err)
	} else if privateKeyAsBytes == nil {
		log.Debugf("Private key could not be found")
		return nil,fmt.Errorf("Private key could not be found.")
	}

	block, _ := pem.Decode(privateKeyAsBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Warningf("privateKeyAsBytes %s", privateKeyAsBytes)
		log.Errorf("Error decoding private key: block %v", block)
		return nil,fmt.Errorf("Error decoding private key")
	}
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			log.Errorf("Error decrypting block: err %v", err)
			return nil,fmt.Errorf("Error decrypting block: err %v", err)
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		log.Errorf("Error parsing key: err %v", err)
		return nil,fmt.Errorf("Error parsing key: err %v", err)
	}

	return key,nil
}

func getOrgList(stub shim.ChaincodeStubInterface) ([]string, error) {

	pkQueryString := fmt.Sprintf("{\"selector\":{\"docType\":\"%s\"}}", PK)

	resultsIterator, err := stub.GetQueryResult(pkQueryString)
	if err != nil {
		log.Errorf("Error querying orgs: err %v", err)
		return nil,fmt.Errorf("Error querying orgs: err %v", err)
	}

	defer resultsIterator.Close()

	orgs := []string{}

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			log.Errorf("Error iterating public keys: err %v", err)
			return nil,fmt.Errorf("Error iterating  public keys: err %v", err)
		}
		var pkTx PKTransaction
		if err := json.Unmarshal(queryResponse.Value, &pkTx); err != nil {
			log.Errorf("Error unmarshaling PKTransaction json to struct: err %v", err)
			return nil,fmt.Errorf("Error unmarshaling PKTransaction json to struct: err %v", err)
		}
		orgs = append(orgs, pkTx.Org)
	}

	return orgs,nil
}

func getOrgPublicKey(stub shim.ChaincodeStubInterface, org string) (*rsa.PublicKey, error) {
	publicKeyTxAsBytes, err := stub.GetState(org)
	if err != nil {
		log.Debugf("Public key could not be found: err %v", err)
		return nil,fmt.Errorf("Public key could not be found: err %v", err)
	} else if publicKeyTxAsBytes == nil {
		log.Debugf("Public key could not be found")
		return nil,fmt.Errorf("Public key could not be found")
	}

	var publicKeyTx PKTransaction
	err = json.Unmarshal(publicKeyTxAsBytes, &publicKeyTx)
	if err != nil {
		log.Errorf("Error unmarshaling PrivateData json to struct: err %v", err)
		return nil,fmt.Errorf("Error unmarshaling PrivateData json to struct: err %v", err)
	}

	block, _ := pem.Decode(publicKeyTx.PublicKey)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		log.Warningf("publicKeyTx.PublicKey %s", publicKeyTx.PublicKey)
		log.Errorf("Error decoding public key: block %v", block)
		return nil,fmt.Errorf("Error decoding public key")
	}
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			log.Errorf("Error decrypting org public key: org %s err %v", org, err)
			return nil,fmt.Errorf("Error decrypting org public key: org %s err %v", org, err)
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		log.Errorf("Error parsing org public key: org %s err %v", org, err)
		return nil,fmt.Errorf("Error parsing org public key: org %s err %v", org, err)
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		log.Errorf("Error casting org public key: org %s", org)
		return nil,fmt.Errorf("Error casting org public key: org %s", org)
	}

	return key,nil
}

func getOrgPublicKeyList(stub shim.ChaincodeStubInterface) ([]string, []*rsa.PublicKey, error) {
	pkQueryString := fmt.Sprintf("{\"selector\":{\"docType\":\"%s\"}}", PK)

	resultsIterator, err := stub.GetQueryResult(pkQueryString)
	if err != nil {
		log.Errorf("Error querying orgs: err %v", err)
		return nil,nil,fmt.Errorf("Error querying orgs: err %v", err)
	}

	defer resultsIterator.Close()

	orgs := []string{}
	pks := []*rsa.PublicKey{}

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			log.Errorf("Error iterating public keys: err %v", err)
			return nil,nil,fmt.Errorf("Error iterating  public keys: err %v", err)
		}
		var pkTx PKTransaction
		if err := json.Unmarshal(queryResponse.Value, &pkTx); err != nil {
			log.Errorf("Error unmarshaling PKTransaction json to struct: err %v", err)
			return nil,nil,fmt.Errorf("Error unmarshaling PKTransaction json to struct: err %v", err)
		}
		block, _ := pem.Decode(pkTx.PublicKey)
		if block == nil || block.Type != "RSA PUBLIC KEY" {
			log.Warningf("pkTx.PublicKey %s", pkTx.PublicKey)
			log.Errorf("Error decoding public key: block %v", block)
			return nil,nil,fmt.Errorf("Error decoding public key")
		}
		enc := x509.IsEncryptedPEMBlock(block)
		b := block.Bytes
		if enc {
			b, err = x509.DecryptPEMBlock(block, nil)
			if err != nil {
				log.Errorf("Error decrypting org public key: org %s err %v", pkTx.Org, err)
				return nil,nil,fmt.Errorf("Error decrypting org public key: org %s err %v", pkTx.Org, err)
			}
		}
		ifc, err := x509.ParsePKIXPublicKey(b)
		if err != nil {
			log.Errorf("Error parsing org public key: org %s err %v", pkTx.Org, err)
			return nil,nil,fmt.Errorf("Error parsing org public key: org %s err %v", pkTx.Org, err)
		}
		key, ok := ifc.(*rsa.PublicKey)
		if !ok {
			log.Errorf("Error casting org public key: org %s", pkTx.Org)
			return nil,nil,fmt.Errorf("Error casting org public key: org %s", pkTx.Org)
		}
		orgs = append(orgs, pkTx.Org)
		pks = append(pks, key)
	}

	return orgs,pks,nil
}//TODO delete

func getResponse(stub shim.ChaincodeStubInterface, categoryName string, subjectName string, org string) (*RespTransaction, error) {
	query := fmt.Sprintf("{\"selector\":{\"docType\":\"%s\",\"categoryName\":\"%s\",\"subjectName\":\"%s\",\"creator\":\"%s\",\"org\":\"%s\"}}", RESP, categoryName, subjectName, org, CORE_PEER_LOCALMSPID)
	resultsIterator, err := stub.GetQueryResult(query)
	if err != nil {
		log.Errorf("Error querying responses: err %v", err)
		return nil, fmt.Errorf("Error querying responses: err %v", err)
	}
	log.Debug("Queryed blockchain.")
	var most_recent RespTransaction
	set := false
	for resultsIterator.HasNext() {
			queryResponse, err := resultsIterator.Next()
			if err != nil {
				log.Errorf("Error iterating responses: err %v", err)
				return nil, fmt.Errorf("Error iterating responses: err %v", err)
			}
			var respTx RespTransaction
			err = json.Unmarshal(queryResponse.Value, &respTx)
			if err != nil {
				log.Errorf("Error unmarshaling PrivateData json to struct: err %v", err)
				return nil, fmt.Errorf("Error unmarshaling PrivateData json to struct: err %v", err)
			}
			if !set {
				most_recent = respTx
				set = true
			} else if most_recent.Timestamp < respTx.Timestamp {
				most_recent = respTx
			}
	}
	if !set {
		log.Error("RespTransaction not found")
		return nil, fmt.Errorf("Responses not found")
	}

	return &most_recent, nil
}

func sendRevoke(stub shim.ChaincodeStubInterface, categoryName string, subjectName string, org string) pb.Response {
	timestamp,err := stub.GetTxTimestamp()
	if err != nil {
		log.Errorf("Error getting transaction timestamp: err %v", err)
		return shim.Error("Error getting transaction timestamp: err " + err.Error())
	}
	revokeResp := &RespTransaction{
		ObjectType: RESP,
		Category: 	categoryName,
		Subject: 		subjectName,
		Org:				org,
		Response:   REVOKE,
		EncKey:			nil,
		EncNonce:		nil,
		Creator: 		CORE_PEER_LOCALMSPID,
		Timestamp:  timestamp.GetSeconds(),
	}
	revokeRespJSONasBytes, err := json.Marshal(revokeResp)
	if err != nil {
		log.Errorf("Error marshaling RespTransaction struct to json: err %v", err)
		return shim.Error("Error marshaling RespTransaction struct to json: err " + err.Error())
	}

	respEvent := &Event{
		Category: 	categoryName,
		Subject: 		subjectName,
		Org:				org,
		Creator:    CORE_PEER_LOCALMSPID,
	}
	eventJSONasBytes, err := json.Marshal(respEvent)
	if err != nil {
		log.Errorf("Error marshaling Event struct to json: err %v", err)
		return shim.Error("Error marshaling Event struct to json: err " + err.Error())
	}
	log.Debug("Marshaled Event struct to json.")

	key := RESP + "-" + categoryName + "-" + subjectName + "-" + CORE_PEER_LOCALMSPID + "-" + strconv.Itoa(int(timestamp.GetSeconds()))
	err = stub.PutState(key, revokeRespJSONasBytes)
	if err != nil {
		log.Errorf("Error storing RespTransaction struct in blockchain: key %s err %v", key, err)
		return shim.Error("Error storing access response in blockchain: err " + err.Error())
	}

	log.Debug("Stored revokeResp in blockchain")

	err = stub.SetEvent(RespEventPrefix + org, eventJSONasBytes)
	if err != nil {
		log.Errorf("Error storing RespTransaction struct in blockchain: key %s err %v", key, err)
		return shim.Error("Error storing access response in blockchain: err " + err.Error())
	}
	log.Debug("Stored respEvent in blockchain.")

	return shim.Success([]byte("Revoked: categoryName " + categoryName + " subjectName " + subjectName + " org " + org))
}

func main() {
	CORE_PEER_LOCALMSPID = os.Getenv("CORE_PEER_LOCALMSPID")
	if CORE_PEER_LOCALMSPID == "" {
		log.Fatalf("CORE_PEER_LOCALMSPID not set")
	}
	StateDB = "StateDB" + CORE_PEER_LOCALMSPID
	PrivateDB = "PrivateDB"+ CORE_PEER_LOCALMSPID
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)
	backendLeveled := logging.AddModuleLevel(backend)
	backendLeveled.SetLevel(logging.CRITICAL, "")
	logging.SetBackend(backendLeveled, backendFormatter)

	err := shim.Start(new(ChineseWall))
	if err != nil {
		log.Fatal(err)
	}
}
