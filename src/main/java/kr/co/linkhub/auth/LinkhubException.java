/*
 * Copyright 2006-2014 linkhub.co.kr, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package kr.co.linkhub.auth;

/**
 * Linkhub Operation Exception.
 * @author KimSeongjun
 * @see http://www.linkhub.co.kr
 * @version 1.0.2
 */
public class LinkhubException extends Exception {
	private static final long serialVersionUID = 1L;

	private long code;
	
	public LinkhubException(long code , String Message) {
		super(Message);
		this.code = code;
	}
	
	public LinkhubException(long code , String Message, Throwable innerException) {
		super(Message,innerException);
		this.code = code;
	}
	
	/**
	 * Return Linkhub's result Error code. (ex. -11010009)
	 * In case of -99999999, check the getMessage() for detail.
	 * @return error code.
	 */
	public long getCode() {
		return code;
	}
	
}
