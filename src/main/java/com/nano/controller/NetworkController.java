package com.nano.controller;

import com.nano.common.vo.CommonResult;
import com.nano.core.End2endIT;

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
@Api(tags = "NetworkController", description = "网络相关控制器")
@RequestMapping("/network")
public class NetworkController {


    @Autowired
    private End2endIT end2endIT;

    /**
     * 接收平板上传的各种仪器数据并解析并存储
     *
     * @return 是否成功
     */
    @GetMapping("/init")
    @ApiOperation(value = "初始化网络")
    public CommonResult<String> handleCollectorPostData() {

        end2endIT.init();

        // 进行数据处理并返回结果
        return CommonResult.success();
    }

}
