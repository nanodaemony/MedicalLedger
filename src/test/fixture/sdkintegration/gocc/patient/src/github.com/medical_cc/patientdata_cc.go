package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

var logger = shim.NewLogger("medical_cc0")

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct {
}

type PatientDataEntity struct {
	TreatmentId          string
	DataSaveUrl          string
	DataMessageDigest    string
	DataSignatureDoctor  string
	DataSignaturePatient string
	PatientPseudonymId   string
	DoctorPseudonymId    string
	Timestamp            int64
}

// 链码初始化
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Info("########### Chaincode example_cc Init ###########")
	return shim.Success(nil)
}

// Invoke方法
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {

	logger.Info("########### example_cc Invoke ###########")
	// 获取方法与参数
	function, args := stub.GetFunctionAndParameters()

	if function == "delete" {
		return t.delete(stub, args)
	}

	if function == "query" {
		return t.query(stub, args)
	}

	if function == "queryByPseudonymId" {
		return t.queryByPseudonymId(stub, args)
	}

	if function == "queryByTreatmentId" {
		return t.queryByTreatmentId(stub, args)
	}

	if function == "savePatientData" {
		return t.savePatientData(stub, args)
	}

	logger.Errorf("Unknown action, check the first argument, must be one of 'queryByPseudonymId', 'queryByTreatmentId', or 'savePatientData'. But got: %v", args[0])
	return shim.Error(fmt.Sprintf("Unknown action, check the first argument, must be one of 'queryByPseudonymId', 'queryByTreatmentId', or 'savePatientData'. But got: %v", args[0]))
}

/**
 * Save patient data to the ledger.
 * @args[0] pseudonymId 病人伪身份ID
 * @args[1] newDataString 传入的新的病人数据实体
 */
//func (t *SimpleChaincode) savePatientData(stub shim.ChaincodeStubInterface, args []string) pb.Response {
//	// 伪身份PID
//	var pseudonymId string
//	// 传入的新数组的字符串
//	var newDataString string
//	// 解析后的新的病人数据Entity
//	var newDataEntity PatientDataEntity
//	// 解析后的历史列表
//	//var historyEntityList []PatientDataEntity
//
//	// 参数长度判断
//	if len(args) != 2 {
//		return shim.Error("Incorrect number of arguments. Expecting 1, function followed by 2 names and 1 value")
//	}
//	// 获取传入的参数
//	pseudonymId = args[0]
//	newDataString = args[1]
//
//	// 将新的数据解析成实体
//	err := json.Unmarshal([]byte(newDataString), &newDataEntity)
//	if err != nil{
//		return shim.Error("新的Patient数据解析错误.原始数据:" + newDataString + " " + err.Error())
//	}
//
//	// 获取PID用户的历史数据
//	historyDataByte, err := stub.GetState(pseudonymId)
//	// 无法获取历史状态信息
//	if err != nil{
//		return shim.Error("账本中没有这个用户PID:" + newDataEntity.PatientPseudonymId)
//	}
//	// 说明没有用户的历史数据
//	if historyDataByte == nil || len(historyDataByte) == 0 {
//		// 直接将新的数据JSON字符串存入账本即可
//		err = stub.PutState(pseudonymId, []byte(newDataString))
//		// 说明有这个用户的历史数据
//	} else {
//		// historyEntityList = strings.Split(str, ",")
//		// 将历史数据进行解析成列表
//		//err = json.Unmarshal(historyDataByte, &historyEntityList)
//		//// 解析错误
//		//if err != nil{
//		//	return shim.Error("历史Patient数据解析错误:" + string(historyDataByte) + err.Error())
//		//}
//		// 新的数据加入列表
//		//historyEntityList = append(historyEntityList, newDataEntity)
//		// 序列化成JSON字符串进行存储
//		//resJsonString, _ := json.Marshal(historyEntityList)
//		resString := "^*$" + string(historyDataByte)
//		err = stub.PutState(pseudonymId, []byte(resString))
//		if err != nil{
//			return shim.Error("Patient data save to ledger error.")
//		}
//	}
//	return shim.Success(nil)
//}

func (t *SimpleChaincode) savePatientData(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 伪身份PID
	var pseudonymId string
	// 传入的新数组的字符串
	var newDataString string
	// 解析后的新的病人数据Entity
	var newDataEntity PatientDataEntity

	// 参数长度判断
	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 1, function followed by 2 names and 1 value")
	}
	// 获取传入的参数
	pseudonymId = args[0]
	newDataString = args[1]

	// 将新的数据解析成实体
	err := json.Unmarshal([]byte(newDataString), &newDataEntity)
	if err != nil {
		return shim.Error("新的Patient数据解析错误.原始数据:" + newDataString + " " + err.Error())
	}

	// 获取PID用户的历史数据
	historyDataByte, err := stub.GetState(pseudonymId)
	// 无法获取历史状态信息
	if err != nil {
		return shim.Error("账本中没有这个用户PID:" + newDataEntity.PatientPseudonymId)
	}
	// 说明没有用户的历史数据
	if historyDataByte == nil || len(historyDataByte) == 0 {
		// 直接将新的数据JSON字符串存入账本即可
		err = stub.PutState(pseudonymId, []byte(newDataString))
		// 说明有这个用户的历史数据
	} else {
		// 构造新的存储的字符串
		resString := string(historyDataByte) + "^*$" + newDataString
		err = stub.PutState(pseudonymId, []byte(resString))
		if err != nil {
			return shim.Error("Patient data save to ledger error.")
		}
	}
	return shim.Success(nil)
}

///**
// * 通过伪身份ID查询用户的全部数据
// * @args[0] pseudonymId 病人伪身份ID
// */
//func (t *SimpleChaincode) queryByPseudonymId(stub shim.ChaincodeStubInterface, args []string) pb.Response {
//
//	var pseudonymId string
//	var err error
//	// 判断参数
//	if len(args) != 1 {
//		return shim.Error("Incorrect number of arguments. Expecting name of the person to query.")
//	}
//
//	// 获取参数
//	pseudonymId = args[0]
//
//	// 从账本获取Byte形式的数据
//	historyDataByte, err := stub.GetState(pseudonymId)
//	if err != nil {
//		jsonResp := "{\"Error\":\"Failed to get state for " + pseudonymId + "\"}"
//		return shim.Error(jsonResp)
//	}
//	if historyDataByte == nil {
//		jsonResp := "{\"Error\":\"Nil amount for " + pseudonymId + "\"}"
//		return shim.Error(jsonResp)
//	}
//	jsonResp := "{\"Name\":\"" + pseudonymId + "\",\"Amount\":\"" + string(historyDataByte) + "\"}"
//	logger.Infof("Query Response:%s\n", jsonResp)
//	return shim.Success(historyDataByte)
//}

/**
 * 通过伪身份ID查询用户的全部数据
 * @args[0] pseudonymId 病人伪身份ID
 */
func (t *SimpleChaincode) queryByPseudonymId(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	var pseudonymId string
	var err error
	// 判断参数
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting name of the person to query.")
	}

	// 获取参数
	pseudonymId = args[0]

	// 从账本获取Byte形式的数据
	historyDataByte, err := stub.GetState(pseudonymId)
	if err != nil {
		jsonResp := "{\"Error\":\"Failed to get state for " + pseudonymId + "\"}"
		return shim.Error(jsonResp)
	}
	if historyDataByte == nil {
		jsonResp := "{\"Error\":\"Nil amount for " + pseudonymId + "\"}"
		return shim.Error(jsonResp)
	}
	jsonResp := "{\"Name\":\"" + pseudonymId + "\",\"Amount\":\"" + string(historyDataByte) + "\"}"
	logger.Infof("Query Response:%s\n", jsonResp)
	return shim.Success(historyDataByte)
}

/**
 * 通过伪身份ID以及治疗ID查询用户的数据
 * @args[0] pseudonymId 病人伪身份ID
 * @args[1] targetTreatmentId 需要查询的目标治疗ID
 */
//func (t *SimpleChaincode) queryByTreatmentId(stub shim.ChaincodeStubInterface, args []string) pb.Response {
//	// 伪身份ID
//	var pseudonymId string
//	// 待查找的治疗ID
//	var targetTreatmentId string
//	// 历史数据数组
//	var historyEntityList []PatientDataEntity
//	var err error
//
//	if len(args) != 2 {
//		return shim.Error("Incorrect number of arguments. PseudonymId and TargetTreatmentId are needed.")
//	}
//	// 获取参数
//	pseudonymId = args[0]
//	targetTreatmentId = args[1]
//
//	// 从账本获取Byte形式的数据
//	historyDataByte, err := stub.GetState(pseudonymId)
//
//	// 账本获取历史数据失败
//	if err != nil {
//		return shim.Error("Can not find history patient data from ledger.")
//	}
//
//	// 说明查找的值为空
//	if historyDataByte == nil || len(historyDataByte) == 0 {
//		return shim.Error("The value of " + pseudonymId + " is null.")
//	}
//
//	// 将历史数据解析成目标数组
//	err = json.Unmarshal([]byte(historyDataByte), &historyEntityList)
//	// 遍历寻找符合要求的ID
//	for _, entity := range historyEntityList {
//		if entity.TreatmentId == targetTreatmentId {
//			// 将目标Entity序列化成JSON格式
//			entityString, _ := json.Marshal(entity)
//			return shim.Success(entityString)
//		}
//	}
//	return shim.Error("There is no target treatmentId in the ledger. which is " + targetTreatmentId)
//}

func (t *SimpleChaincode) queryByTreatmentId(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 伪身份ID
	var pseudonymId string
	// 待查找的治疗ID
	var targetTreatmentId string
	// 历史数据数组
	var historyDataList []string
	var err error

	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. PseudonymId and TargetTreatmentId are needed.")
	}
	// 获取参数
	pseudonymId = args[0]
	targetTreatmentId = args[1]

	// 从账本获取Byte形式的数据
	historyDataByte, err := stub.GetState(pseudonymId)

	// 账本获取历史数据失败
	if err != nil {
		return shim.Error("Can not find history patient data from ledger.")
	}
	// 说明查找的值为空
	if historyDataByte == nil || len(historyDataByte) == 0 {
		return shim.Error("The value of " + pseudonymId + " is null.")
	}
	// 将历史数据解析成目标数组
	historyDataList = strings.Split(string(historyDataByte), "^*$")

	// err = json.Unmarshal([]byte(historyDataByte), &historyEntityList)
	// 遍历寻找符合要求的ID
	res := ""
	for _, data := range historyDataList {
		res = res + data + "\n\n"
		if strings.Contains(string(data), targetTreatmentId) {
			return shim.Success([]byte(data))
		}
	}
	return shim.Error("There is no target treatmentId in the ledger. which is :" + string(res))
}

// Query callback representing the query of a chaincode
func (t *SimpleChaincode) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	var pid string
	var err error

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting name of the person to query.")
	}

	pid = args[0]

	// Get the state from the ledger
	Avalbytes, err := stub.GetState(pid)
	if err != nil {
		jsonResp := "{\"Error\":\"Failed to get state for " + pid + "\"}"
		return shim.Error(jsonResp)
	}

	if Avalbytes == nil {
		jsonResp := "{\"Error\":\"Nil amount for " + pid + "\"}"
		return shim.Error(jsonResp)
	}

	jsonResp := "{\"Name\":\"" + pid + "\",\"Amount\":\"" + string(Avalbytes) + "\"}"
	logger.Infof("Query Response:%s\n", jsonResp)
	return shim.Success(Avalbytes)
}

/**
 * Delete patient data from the ledger.
 */
func (t *SimpleChaincode) delete(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	pid := args[0]

	// Delete the key from the state in ledger
	err := stub.DelState(pid)
	if err != nil {
		return shim.Error("Failed to delete state")
	}

	return shim.Success(nil)
}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		logger.Errorf("Error starting Simple chaincode: %s", err)
	}
}
