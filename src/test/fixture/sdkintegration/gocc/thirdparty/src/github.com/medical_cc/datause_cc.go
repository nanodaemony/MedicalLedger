package main

import (
	"fmt"
	"strings"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

var logger = shim.NewLogger("medical_cc0")

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct {
}


type DataUsageEntity struct {
	SenderPseudonymId   string
	ReceiverPseudonymId    string
	Timestamp            int64
}

// 链码初始化
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Info("########### Chaincode data_usage init ###########")
	return shim.Success(nil)
}

// Invoke方法
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {

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

	if function == "saveDataUsageData" {
		return t.saveDataUsageData(stub, args)
	}

	logger.Errorf("Unknown action, check the first argument, must be one of 'queryByPseudonymId', 'queryByTreatmentId', or 'savePatientData'. But got: %v", args[0])
	return shim.Error(fmt.Sprintf("Unknown action, check the first argument, must be one of 'queryByPseudonymId', 'queryByTreatmentId', or 'savePatientData'. But got: %v", args[0]))
}

/**
 * 保存用户使用信息
 * @args[0] senderPseudonymId 发送者伪身份ID
 * @args[1] receiverPseudonymId 接受者伪身份ID
 * @args[2] treatmentId 被使用数据的治疗ID
 */
func (t *SimpleChaincode) saveDataUsageData(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	// 发送者伪身份PID
	var senderPseudonymId string
	// 接受者伪身份PID
	var receiverPseudonymId string
	// 数据使用记录的JSON字符串
	var dataUsageJsonString string

	// 参数长度判断
	if len(args) != 3 {
		return shim.Error("Incorrect number of arguments. Expecting 1, function followed by 2 names and 1 value")
	}
	// 获取传入的参数
	senderPseudonymId = args[0]
	receiverPseudonymId = args[1]
	dataUsageJsonString = args[2]

	// 获取发送方的历史数据
	senderHistoryDataByte, err := stub.GetState(senderPseudonymId)
	if err != nil {
		return shim.Error("账本中没有这个用户PID:" + string(senderHistoryDataByte))
	}
	// 说明没有用户的历史数据
	if senderHistoryDataByte == nil || len(senderHistoryDataByte) == 0 {
		// 直接将新的数据JSON字符串存入账本即可
		err = stub.PutState(senderPseudonymId, []byte(dataUsageJsonString))
		// 说明有这个用户的历史数据
	} else {
		// 构造新的存储的字符串
		resString := string(senderHistoryDataByte) + "^*$" + dataUsageJsonString
		err = stub.PutState(senderPseudonymId, []byte(resString))
		if err != nil {
			return shim.Error("Patient data save to ledger error.")
		}
	}

	// 获取接收方的历史数据
	receiverHistoryDataByte, err := stub.GetState(receiverPseudonymId)
	if err != nil {
		return shim.Error("账本中没有这个用户PID:" + string(receiverHistoryDataByte))
	}
	// 说明没有用户的历史数据
	if receiverHistoryDataByte == nil || len(receiverHistoryDataByte) == 0 {
		// 直接将新的数据JSON字符串存入账本即可
		err = stub.PutState(receiverPseudonymId, []byte(dataUsageJsonString))
		// 说明有这个用户的历史数据
	} else {
		// 构造新的存储的字符串
		resString := string(receiverHistoryDataByte) + "^*$" + dataUsageJsonString
		err = stub.PutState(receiverPseudonymId, []byte(resString))
		if err != nil {
			return shim.Error("Patient data save to ledger error.")
		}
	}

	return shim.Success(nil)
}


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
 * @args[0] pseudonymId 发送方病人伪身份ID
 * @args[1] targetTreatmentId 需要查询的目标治疗ID
 */
func (t *SimpleChaincode) queryByTreatmentId(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 伪身份ID
	var senderPseudonymId string
	// 待查找的治疗ID
	var targetTreatmentId string
	// 历史数据数组
	var historyDataUsageList []string
	var err error

	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. PseudonymId and TargetTreatmentId are needed.")
	}
	// 获取参数
	senderPseudonymId = args[0]
	targetTreatmentId = args[1]

	// 从账本获取Byte形式的数据
	historyDataByte, err := stub.GetState(senderPseudonymId)

	// 账本获取历史数据失败
	if err != nil {
		return shim.Error("Can not find history patient data from ledger.")
	}
	// 说明查找的值为空
	if historyDataByte == nil || len(historyDataByte) == 0 {
		return shim.Error("The value of " + senderPseudonymId + " is null.")
	}
	// 将历史数据解析成目标数组
	historyDataUsageList = strings.Split(string(historyDataByte), "^*$")

	// err = json.Unmarshal([]byte(historyDataByte), &historyEntityList)
	// 遍历寻找符合要求的ID
	res := ""
	for _, data := range historyDataUsageList {
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
