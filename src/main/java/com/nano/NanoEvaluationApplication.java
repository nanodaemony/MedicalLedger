package com.nano;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.web.bind.annotation.CrossOrigin;

import lombok.extern.slf4j.Slf4j;

/**
 * 主函数
 * @author nano
 */
@SpringBootApplication
@CrossOrigin
@ComponentScan("com.nano.msc")
@Slf4j
@EnableAsync
public class NanoEvaluationApplication {

	public static void main(String[] args) {
		SpringApplication.run(NanoEvaluationApplication.class, args);
		log.info("成功开启项目...");
	}


}
