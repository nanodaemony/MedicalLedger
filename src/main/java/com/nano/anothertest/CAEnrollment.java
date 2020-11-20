/****************************************************** 
 *  Copyright 2018 IBM Corporation 
 *  Licensed under the Apache License, Version 2.0 (the "License"); 
 *  you may not use this file except in compliance with the License. 
 *  You may obtain a copy of the License at 
 *  http://www.apache.org/licenses/LICENSE-2.0 
 *  Unless required by applicable law or agreed to in writing, software 
 *  distributed under the License is distributed on an "AS IS" BASIS, 
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 *  See the License for the specific language governing permissions and 
 *  limitations under the License.
 */

package com.nano.anothertest;

import org.hyperledger.fabric.sdk.Enrollment;

import java.io.Serializable;
import java.security.PrivateKey;

/**
 * 自定义Enrollment metadata
 * @author nano
 */
public class CAEnrollment implements Enrollment, Serializable {

	private static final long serialVersionUID = 550416591376968096L;

	/**
	 * 私钥
	 */
	private PrivateKey key;

	/**
	 * 证书
	 * OpenSSL使用PEM文件格式存储证书和密钥
	 */
	private String cert;

	public CAEnrollment(PrivateKey privateKey, String signedPem) {
		this.key = privateKey;
		this.cert = signedPem;
	}

	@Override
	public PrivateKey getKey() {
		return key;
	}

	@Override
	public String getCert() {
		return cert;
	}
}
