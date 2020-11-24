package com.nano.controller;

import com.nano.common.vo.CommonResult;
import com.nano.core.MedicalCore;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;

/**
 * Description: 网络相关的Controller
 *
 * @version: 1.0
 * @author: nano
 * @date: 2020/11/14 17:12
 */
@RestController
@Slf4j
@Api(tags = "MedicalController", description = "医疗控制器")
@RequestMapping("/medical")
public class MedicalController {


    @Autowired
    private MedicalCore medicalCore;

    /**
     * 接收平板上传的各种仪器数据并解析并存储
     *
     * @return 是否成功
     */
    @GetMapping("/init")
    @ApiOperation(value = "初始化网络")
    public CommonResult<String> init() {
        medicalCore.initConfig();
        medicalCore.initChainCodeForPatient();
        medicalCore.initChainCodeForThirdParty();
        // 进行数据处理并返回结果
        return CommonResult.success();
    }


    @GetMapping("/initChainCodeForPatient")
    @ApiOperation(value = "为Patient组织安装链码")
    public CommonResult<String> initChainCodeForPatient() {
        // 进行数据处理并返回结果
        return CommonResult.success();
    }


    @GetMapping("/initChainCodeForThirdParty")
    @ApiOperation(value = "为ThirdParty组织安装链码")
    public CommonResult<String> initChainCodeForThirdParty() {
        // 进行数据处理并返回结果
        return CommonResult.success();
    }


    @GetMapping("/query")
    @ApiOperation(value = "查询")
    public CommonResult<String> qury() throws Exception{

//        log.info("查询MyChannel");
//        medicalCore.queryUserMyChannel();
//        log.info("查询PatientChannel");
//        medicalCore.queryUserPatientChannel();
        // 进行数据处理并返回结果
        return CommonResult.success();
    }

}
