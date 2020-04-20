package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

const StateDB = "stateDB"
const PrivateDB = "privateDB"
const PublicKeyList = "PublicKeyList"
const PublicKeyIndex = "pk~name"

// My unique entity identifier
var CORE_PEER_LOCALMSPID string

// Path to rsa keys
var CORE_PEER_PUBLIC_KEY_FILE string

// Transaction type types that are recognized by this chaincode
const (
	DATA int = iota
	REQ
	RESP
	CAT
	SUB
	PK
)

type PKTransaction struct {
	ObjectType int    `json:"docType"`
	Entity     string `json:"entity"`
	PublicKey  []byte `json:"publicKey"`
}

type ReqTransaction struct {
	ObjectType int    `json:"docType"`
	Category   string `json:"category"`
	Subject    string `json:"subject"`
	Entity     string `json:"entity"`
}

type DataTransaction struct {
	ObjectType int    `json:"docType"`
	Category   string `json:"category"`
	Subject    string `json:"subject"`
	Entity     string `json:"entity"`
}

// Category to describe user defined categories in private db
type PrivateCategory struct {
	Name     string
	Subjects map[string]PrivateSubject
	Creator  string
}

// Category to describe user defined categories on blockchain
type PublicCategory struct {
	ObjectType int                      `json:"docType"`
	Name       string                   `json:"name"`
	Subjects   map[string]PublicSubject `json:"subjects"`
	Creator    string                   `json:"creator"`
}

// Subject to describe data specific subject for a certain category on blockchain
type PublicSubject struct {
	ObjectType int                 `json:"docType"`
	Name       string              `json:"name"`
	EncData    map[string][][]byte `json:"encData"`
	Creator    string              `json:"creator"`
	EncKeys    map[string][]byte   `json:"encKeys"`
	EncNonces  map[string][]byte   `json:"encNonces"`
}

// Subject to describe data specific subject for a certain category in private db
type PrivateSubject struct {
	Name       string
	Data       []string
	AccessList []string
	Creator    string
	Keys       map[string][]byte
	Nonces     map[string][]byte
}

type PrivateData struct {
	Category	string
	Subject 	string
	Data      [][]byte
}

type ChineseWall struct {
}

func (t *ChineseWall) Init(stub shim.ChaincodeStubInterface) pb.Response {
	priv, err := ioutil.ReadFile(CORE_PEER_PUBLIC_KEY_FILE)
	if err != nil {
		log.Fatalf("Cannot read public key encryption file %s: %v", CORE_PEER_PUBLIC_KEY_FILE, err)
		return shim.Error("Cannot read public key encryption file " + CORE_PEER_PUBLIC_KEY_FILE + ":" + err.Error())
	}

	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return shim.Error(err.Error())
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return shim.Error(err.Error())
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return shim.Error(err.Error())
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	pkTransaction := PKTransaction{
		ObjectType: PK,
		Entity:     CORE_PEER_LOCALMSPID,
		PublicKey:  pubBytes,
	}

	pkTransactionAsBytes, err := json.Marshal(pkTransaction)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutState("PK-"+CORE_PEER_LOCALMSPID, pkTransactionAsBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *ChineseWall) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()
	log.Println("Invoke " + function)

	// Handle different functions
	switch function {
	case "newCategory":
		//create a new category
		return t.newCategory(stub, args)
	case "newSubject":
		//create a new subject
		return t.newSubject(stub, args)
	case "newData":
		//add data for a subject
		return t.newData(stub, args)
	case "requestSubject":
		//request access to data from a subject
		return t.requestSubject(stub, args)
	case "readSubject":
		//read data from a subject if accessible
		return t.readSubject(stub, args)
	// case "listSubjects":
	// 	//list subjects that are accessible
	// 	return t.listSubjects(stub, args)
	default:
		//error
		log.Println("Invoke did not find func: " + function)
		return shim.Error("Received unknown function invocation")
	}
}

func (t *ChineseWall) newCategory(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Expecting category name as argument.")
	}
	if len(args[0]) <= 0 {
		return shim.Error("Category Name must be a non-empty string.")
	}
	categoryName := "Category-" + args[0]

	_, err := getPrivateCategory(stub, categoryName)
	if err == nil {
		return shim.Error("This category already exists: " + categoryName)
	}

	privateCategory := &PrivateCategory{
		Name:     categoryName,
		Subjects: map[string]PrivateSubject{},
		Creator:  CORE_PEER_LOCALMSPID,
	}

	privateCategoryJSONasBytes, err := json.Marshal(privateCategory)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutPrivateData(StateDB, categoryName, privateCategoryJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	publicCategory := &PublicCategory{
		ObjectType: CAT,
		Name:       categoryName,
		Subjects:   map[string]PublicSubject{},
		Creator:    CORE_PEER_LOCALMSPID,
	}

	publicCategoryJSONasBytes, err := json.Marshal(publicCategory)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutState(categoryName, publicCategoryJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *ChineseWall) newSubject(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		return shim.Error("Expecting 2 arguments.")
	}
	if len(args[0]) <= 0 {
		return shim.Error("Subject Name must be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		return shim.Error("Subject Category must be a non-empty string.")
	}

	subjectName := "Subject-" + args[0]
	categoryName := "Category-" + args[1]

	privateCategory, err := getPrivateCategory(stub, categoryName)
	if err != nil {
		log.Println("This category cannot be found: " + categoryName + " " + err.Error())
		return shim.Error(err.Error())
	}

	_, ok := privateCategory.Subjects[subjectName]
	if ok {
		log.Println("This subject " + subjectName + " for the category " + categoryName + " already exists.")
		return shim.Error("This subject " + subjectName + " for the category " + categoryName + " already exists.")
	}

	privateSubject := PrivateSubject{
		Name:       subjectName,
		Data:       []string{},
		AccessList: []string{},
		Creator:    CORE_PEER_LOCALMSPID,
		Keys:       map[string][]byte{},
		Nonces:     map[string][]byte{},
	}

	entities, err := getEntityList(stub)
	if err != nil {
		log.Println("Cannot get entity list: " + err.Error())
		return shim.Error("Cannot get entity list: " + err.Error())
	}

	for _, entity := range entities {
		key := make([]byte, 64)
		_, err := rand.Read(key)
		if err != nil {
			return shim.Error(err.Error())
		}

		nonce := make([]byte, 12)
		_, err = rand.Read(nonce)
		if err != nil {
			return shim.Error(err.Error())
		}

		privateSubject.Keys[entity] = key
		privateSubject.Nonces[entity] = nonce
	}

	privateCategory.Subjects[subjectName] = privateSubject

	privateCategoryJSONasBytes, err := json.Marshal(privateCategory)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutPrivateData(StateDB, categoryName, privateCategoryJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	publicCategory, err := getPublicCategory(stub, categoryName)
	if err != nil {
		log.Println("This category cannot be found: " + categoryName + " " + err.Error())
		return shim.Error(err.Error())
	}

	_, ok = publicCategory.Subjects[subjectName]
	if ok {
		log.Println("This subject " + subjectName + " for the category " + categoryName + " already exists.")
		return shim.Error("This subject " + subjectName + " for the category " + categoryName + " already exists.")
	}

	publicSubject := PublicSubject{
		ObjectType: SUB,
		Name:       subjectName,
		EncData:    map[string][][]byte{},
		Creator:    CORE_PEER_LOCALMSPID,
		EncKeys:    map[string][]byte{},
		EncNonces:  map[string][]byte{},
	}

	publicCategory.Subjects[subjectName] = publicSubject

	publicCategoryJSONasBytes, err := json.Marshal(publicCategory)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutState(categoryName, publicCategoryJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *ChineseWall) newData(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 3 {
		return shim.Error("Expecting 3 arguments.")
	}
	if len(args[0]) <= 0 {
		return shim.Error("Subject Name must be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		return shim.Error("Subject Category must be a non-empty string.")
	}
	if len(args[2]) <= 0 {
		return shim.Error("Data must be a non-empty string.")
	}
	subjectName := "Subject-" + args[0]
	categoryName := "Category-" + args[1]
	data := args[2]

	privateCategory, err := getPrivateCategory(stub, categoryName)
	if err != nil {
		log.Println("This category cannot be found: " + categoryName + " " + err.Error())
		return shim.Error(err.Error())
	}

	privateSubject, ok := privateCategory.Subjects[subjectName]
	if !ok {
		log.Println("This subject " + subjectName + " for the category " + categoryName + " does not exist.")
		return shim.Error("This subject " + subjectName + " for the category " + categoryName + " does not exist.")
	}

	publicCategory, err := getPublicCategory(stub, categoryName)
	if err != nil {
		log.Println("This category cannot be found: " + categoryName + " " + err.Error())
		return shim.Error(err.Error())
	}

	publicSubject, ok := publicCategory.Subjects[subjectName]
	if !ok {
		log.Println("This subject " + subjectName + " for the category " + categoryName + " does not exist.")
		return shim.Error("This subject " + subjectName + " for the category " + categoryName + " does not exist.")
	}

	for entity, key := range privateSubject.Keys {
		nonce := privateSubject.Nonces[entity]
		encData, err := prEncrypt([]byte(data), key, nonce)
		if err != nil {
			return shim.Error(err.Error())
		}
		publicSubject.EncData[entity] = append(publicSubject.EncData[entity], encData)
	}

	publicCategory.Subjects[subjectName] = publicSubject

	publicCategoryJSONasBytes, err := json.Marshal(publicCategory)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutState(categoryName, publicCategoryJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *ChineseWall) requestSubject(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Expecting 2 arguments.")
	}
	if len(args[0]) <= 0 {
		return shim.Error("Subject Name must be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		return shim.Error("Subject Category must be a non-empty string.")
	}

	subjectName := "Subject-" + args[0]
	categoryName := "Category-" + args[1]

	privateCategory, err := getPrivateCategory(stub, categoryName)
	if err == nil {
		_, ok := privateCategory.Subjects[subjectName]
		if ok {
			return shim.Error("Already have access to subject " + subjectName + " in category " + categoryName)
		}
	}

	publicCategory, err := getPublicCategory(stub, categoryName)
	if err != nil {
		log.Println("This category cannot be found: " + categoryName + " " + err.Error())
		return shim.Error("This category cannot be found: " + categoryName + " " + err.Error())
	}

	_, ok := publicCategory.Subjects[subjectName]
	if !ok {
		log.Println("This subject " + subjectName + " for the category " + categoryName + " does not exist.")
		return shim.Error("This subject " + subjectName + " for the category " + categoryName + " does not exist.")
	}

	reqTransaction := &ReqTransaction{
		ObjectType: REQ,
		Category: 	categoryName,
		Subject: 		subjectName,
		Entity: 		CORE_PEER_LOCALMSPID,
	}

	reqTrnasactionJSONasBytes, err := json.Marshal(reqTransaction)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutState("REQ-" + categoryName + "-" + subjectName + "-" + CORE_PEER_LOCALMSPID, reqTrnasactionJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *ChineseWall) readSubject(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		return shim.Error("Expecting 2 arguments.")
	}
	if len(args[0]) <= 0 {
		return shim.Error("Subject Name must be a non-empty string.")
	}
	if len(args[1]) <= 0 {
		return shim.Error("Subject Category must be a non-empty string.")
	}

	subjectName := "Subject-" + args[0]
	categoryName := "Category-" + args[1]

	privateData, err := getPrivateData(stub, categoryName, subjectName)
	if err != nil {
		log.Println(err.Error())
		return shim.Error(err.Error())
	}

	privateDataJSONasBytes, err := json.Marshal(privateData)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(privateDataJSONasBytes)
}

func prEncrypt(plaintext []byte, key []byte, nonce []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

func prDecrypt(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// func puEncrypt(plaintext []byte, publicKey []byte) ([]byte, error) {
//
// }

// func puDecrypt(ciphertext []byte, privateKey []byte) []byte {
// }

func getPrivateCategory(stub shim.ChaincodeStubInterface, categoryName string) (*PrivateCategory, error) {
	privateCategoryAsBytes, err := stub.GetPrivateData(StateDB, categoryName)
	if err != nil {
		return nil, fmt.Errorf("Failed to get state information: " + err.Error())
	} else if privateCategoryAsBytes == nil {
		log.Println("This category does not already exist: " + categoryName)
		return nil, fmt.Errorf("This category does not already exist: " + categoryName)
	}

	var privateCategory PrivateCategory
	err = json.Unmarshal(privateCategoryAsBytes, &privateCategory)
	if err != nil {
		return nil, err
	}

	return &privateCategory, nil
}

func getPublicCategory(stub shim.ChaincodeStubInterface, categoryName string) (*PublicCategory, error) {
	publicCategoryAsBytes, err := stub.GetState(categoryName)
	if err != nil {
		return nil, fmt.Errorf("Failed to get category: " + err.Error())
	}

	var publicCategory PublicCategory
	err = json.Unmarshal(publicCategoryAsBytes, &publicCategory)
	if err != nil {
		return nil, err
	}
	return &publicCategory, nil
}

func getPrivateData(stub shim.ChaincodeStubInterface, categoryName string, subjectName string) ([][]byte, error) {
	privateDataAsBytes, err := stub.GetPrivateData(PrivateDB, categoryName + "-" + subjectName)
	if err != nil {
		return nil, fmt.Errorf("Failed to get data information: " + err.Error())
	} else if privateDataAsBytes == nil {
		log.Println("This data does not exist: " + categoryName + "-" + subjectName)
		return nil, fmt.Errorf("This data does not exist: " + categoryName + "-" + subjectName)
	}

	var privateData PrivateData
	err = json.Unmarshal(privateDataAsBytes, &privateData)
	if err != nil {
		return nil, err
	}

	return privateData.Data, nil
}

func getEntityList(stub shim.ChaincodeStubInterface) ([]string, error) {

	pkQueryString := fmt.Sprintf("{\"selector\":{\"docType\":%s}}", PK)

	resultsIterator, err := stub.GetQueryResult(pkQueryString)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	entities := []string{}

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var pkTx PKTransaction
		if err := json.Unmarshal(queryResponse.Value, &pkTx); err != nil {
			return nil, err
		}
		entities = append(entities, pkTx.Entity)
	}

	return entities, nil
}

func main() {
	CORE_PEER_LOCALMSPID = os.Getenv("CORE_PEER_LOCALMSPID")
	if CORE_PEER_LOCALMSPID == "" {
		log.Fatalf("CORE_PEER_LOCALMSPID not set")
	}
	CORE_PEER_PUBLIC_KEY_FILE = os.Getenv("CORE_PEER_PUBLIC_KEY_FILE")
	if CORE_PEER_PUBLIC_KEY_FILE == "" {
		log.Fatalf("CORE_PEER_PUBLIC_KEY_FILE not set")
	}

	err := shim.Start(new(ChineseWall))
	if err != nil {
		log.Fatal(err)
	}
}
