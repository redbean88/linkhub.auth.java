/*
 * Copyright 2006-2014 innopost.com, Inc. or its affiliates. All Rights Reserved.
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

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.google.gson.Gson;

/**
 * Linkhub TokenBuilder class.
 * @author KimSeongjun
 * @see http://www.linkhub.co.kr
 * @version 1.0.0
 */
public class TokenBuilder {

	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static final String APIVersion = "1.0";
    private static final String ServiceURL = "https://auth.linkhub.co.kr";
    
    private String _LinkID;
    private String _SecretKey;
    private Gson _gsonParser;
    
    private String _recentServiceID;
    private List<String> _recentScope;
    
    private TokenBuilder() {
    	_gsonParser = new Gson();
    }
    
    private static TokenBuilder _singleTone;
    
    /**
     * 
     * @param LinkID 링크아이디
     * @param SecretKey 비밀키
     * @return this for method chaining.
     */
    public static TokenBuilder getInstance(String LinkID,String SecretKey) {
    	if(_singleTone == null) {
    		_singleTone = new TokenBuilder();
    	}
    	_singleTone._LinkID = LinkID;
    	_singleTone._SecretKey = SecretKey;
    	return _singleTone;
    }
    
    /**
     * 
     * @param ServiceID 서비스아이디
     * @return this for method chaining.
     */
    public TokenBuilder ServiceID(String ServiceID) {
    	this._recentServiceID = ServiceID;
    	return this;
    }
    /**
     * 
     * @param scope 스코프
     * @return this for method chaining.
     */
    public TokenBuilder addScope(String scope) {
    	if(_recentScope == null) _recentScope = new ArrayList<String>();
    	if(_recentScope.contains(scope) == false)
    		_recentScope.add(scope);
    
    	return this;
    }
    
    /**
     * 
     * @param AccessID
     * @return Token
     * @throws LinkhubException
     */
    public Token build(String AccessID) throws LinkhubException {
    	return build(AccessID,null);
    }
        
    /**
     * 
     * @param AccessID
     * @param forwardedIP
     * @return Token
     * @throws LinkhubException
     */
    public Token build(String AccessID, String forwardedIP) throws LinkhubException {
    	
    	if(_recentServiceID == null || _recentServiceID.isEmpty()) throw new LinkhubException(-99999999,"서비스아이디가 입력되지 않았습니다.");
    	if(AccessID == null || AccessID.isEmpty()) throw new LinkhubException(-99999999,"AccessID가 입력되지 않았습니다.");
    	
    	HttpURLConnection httpURLConnection;
    	String URI = "/" +  _recentServiceID + "/Token";
    	
		try {
			URL url = new URL(ServiceURL + URI);
			httpURLConnection = (HttpURLConnection) url.openConnection();
		} catch (Exception e) {
			throw new LinkhubException(-99999999, "링크허브 서버 접속 실패",e);
		}

		TokenRequest request = new TokenRequest();
		request.access_id = AccessID;
		request.scope = _recentScope;
		
		String PostData = _gsonParser.toJson(request);
		byte[] btPostData = PostData.getBytes(Charset.forName("UTF-8"));
		
		String invokeTime = getUTCTimeString(new Date());
				
		String signTarget = "POST\n";
		signTarget += md5Base64(btPostData)  + "\n";

		signTarget += invokeTime + "\n";
		signTarget += APIVersion + "\n";
		if(forwardedIP != null && forwardedIP.isEmpty() == false) {
			signTarget += forwardedIP + "\n";
		}
		signTarget += URI;
				
		String Signature = base64Encode(HMacSha1(base64Decode(getSecretKey()), signTarget.getBytes(Charset.forName("UTF-8"))));
		
		httpURLConnection.setRequestProperty("x-lh-date".toLowerCase(), invokeTime);
		httpURLConnection.setRequestProperty("x-lh-version".toLowerCase(), APIVersion);
		if(forwardedIP != null && forwardedIP.isEmpty() == false) {
			httpURLConnection.setRequestProperty("x-lh-forwarded".toLowerCase(), forwardedIP);
		}
		httpURLConnection.setRequestProperty("Authorization","LINKHUB "+ getLinkID() + " " + Signature);
		httpURLConnection.setRequestProperty("Content-Type","application/json; charset=utf8");
		httpURLConnection.setRequestProperty("Content-Length",String.valueOf(btPostData.length));
		
		try {
			httpURLConnection.setRequestMethod("POST");
			httpURLConnection.setUseCaches(false);
			httpURLConnection.setDoOutput(true);
			
			DataOutputStream output = new DataOutputStream(httpURLConnection.getOutputStream());
			output.write(btPostData);
			output.flush();
			output.close();
		} catch (Exception e) {throw new LinkhubException(-99999999, "Fail to POST data to Server.",e);}
		
		String Result = "";
		
		try {
			InputStream input = httpURLConnection.getInputStream();
			Result = fromStream(input);
			input.close();
			
		} catch (IOException e) {
			
			Error error = null;
			
			try
			{
				InputStream input = httpURLConnection.getErrorStream();
				Result = fromStream(input);
				input.close();
				error = _gsonParser.fromJson(Result, Error.class);
			}
			catch(Exception E) {}
			
			if(error == null)
				throw new LinkhubException(-99999999, "Fail to receive data from Server.",e);
			else
				throw new LinkhubException(error.code,error.message);
		}
		
    	return _gsonParser.fromJson(Result, Token.class);
    
    }
    
    /**
     * 
     * @param BearerToken Token.getSession_Token()
     * @return remainPoint
     * @throws LinkhubException
     */
    public double getBalance(String BearerToken) throws LinkhubException {
    	if(BearerToken == null || BearerToken.isEmpty()) throw new LinkhubException(-99999999,"BearerToken이 입력되지 않았습니다.");
    	if(_recentServiceID == null || _recentServiceID.isEmpty()) throw new LinkhubException(-99999999,"서비스아이디가 입력되지 않았습니다.");
    	
    	HttpURLConnection httpURLConnection;
    	String URI = "/" +  _recentServiceID + "/Point";
		try {
			URL url = new URL(ServiceURL + URI);
			httpURLConnection = (HttpURLConnection) url.openConnection();
		} catch (Exception e) {
			throw new LinkhubException(-99999999, "링크허브 서버 접속 실패",e);
		}

		httpURLConnection.setRequestProperty("Authorization","Bearer " + BearerToken);
		
		String Result = "";
		
		try {
			InputStream input = httpURLConnection.getInputStream();
			Result = fromStream(input);
			input.close();
			
		} catch (IOException e) {
			
			Error error = null;
			
			try
			{
				InputStream input = httpURLConnection.getErrorStream();
				Result = fromStream(input);
				input.close();
				error = _gsonParser.fromJson(Result, Error.class);
			}
			catch(Exception E) {}
			
			if(error == null)
				throw new LinkhubException(-99999999, "Fail to receive data from Server.",e);
			else
				throw new LinkhubException(error.code,error.message);
		}
		
    	return _gsonParser.fromJson(Result, PointResult.class).getRemainPoint();
    }
    
    /**
     * 
     * @param BearerToken Token.getSession_Token()
     * @return remainPoint
     * @throws LinkhubException
     */
    public double getPartnerBalance(String BearerToken) throws LinkhubException {
    	if(BearerToken == null || BearerToken.isEmpty()) throw new LinkhubException(-99999999,"BearerToken이 입력되지 않았습니다.");
    	if(_recentServiceID == null || _recentServiceID.isEmpty()) throw new LinkhubException(-99999999,"서비스아이디가 입력되지 않았습니다.");
    	
    	HttpURLConnection httpURLConnection;
    	String URI = "/" +  _recentServiceID + "/PartnerPoint";
		try {
			URL url = new URL(ServiceURL + URI);
			httpURLConnection = (HttpURLConnection) url.openConnection();
		} catch (Exception e) {
			throw new LinkhubException(-99999999, "링크허브 서버 접속 실패",e);
		}

		httpURLConnection.setRequestProperty("Authorization","Bearer " + BearerToken);
		
		String Result = "";
		
		try {
			InputStream input = httpURLConnection.getInputStream();
			Result = fromStream(input);
			input.close();
			
		} catch (IOException e) {
			
			Error error = null;
			
			try
			{
				InputStream input = httpURLConnection.getErrorStream();
				Result = fromStream(input);
				input.close();
				error = _gsonParser.fromJson(Result, Error.class);
			}
			catch(Exception E) {}
			
			if(error == null)
				throw new LinkhubException(-99999999, "Fail to receive data from Server.",e);
			else
				throw new LinkhubException(error.code,error.message);
		}
		
    	return _gsonParser.fromJson(Result, PointResult.class).getRemainPoint();
    }
    
    private String getLinkID() throws LinkhubException {
    	if(_LinkID == null || _LinkID.isEmpty()) throw new LinkhubException(-99999999,"링크아이디가 입력되지 않았습니다.");
    	return _LinkID;
    }
    
    private String getSecretKey() throws LinkhubException {
    	if(_SecretKey == null || _SecretKey.isEmpty()) throw new LinkhubException(-99999999,"비밀키가 입력되지 않았습니다.");
    	return _SecretKey;
    }
    
    private static String md5Base64(byte[] input) {
    	MessageDigest md;
    	byte[] btResult = null;
		try {
			md = MessageDigest.getInstance("MD5");
			btResult = md.digest(input);
		} catch (NoSuchAlgorithmException e) {	}
    	
    	return base64Encode(btResult);
    }
    
    private static byte[] base64Decode(String input) {
    	return DatatypeConverter.parseBase64Binary(input);
    }
    
    private static String base64Encode(byte[] input) {
    	return DatatypeConverter.printBase64Binary(input);
    }
    
    private static byte[] HMacSha1(byte[] key, byte[] input) throws LinkhubException {
    	try
    	{
			SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA1_ALGORITHM);
			Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
			mac.init(signingKey);
			return mac.doFinal(input);
    	}
    	catch(Exception e) 
    	{
    		throw new LinkhubException(-99999999, "Fail to Calculate HMAC-SHA1, Please check your SecretKey.",e);
    	}
	}
    
    private static String getUTCTimeString(Date target) {
    	SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.sss'Z'");
		format.setTimeZone(TimeZone.getTimeZone("UTC"));
		return format.format(target);
    }
    
    private static String fromStream(InputStream input) throws IOException {
    	
    	InputStreamReader is = new InputStreamReader(input,Charset.forName("UTF-8"));
		StringBuilder sb= new StringBuilder();
		BufferedReader br = new BufferedReader(is);
		
		String read = br.readLine();

		while(read != null) {
		    sb.append(read);
		    read = br.readLine();
		}
		
		return sb.toString();
	}
    
    class PointResult {
    	private double remainPoint;

		public double getRemainPoint() {
			return remainPoint;
		}
    }
    
    class Error {
    	private long code;
    	private String message;
    	
		public long getCode() {
			return code;
		}
		public String getMessage() {
			return message;
		}
	}
    
    class TokenRequest {
    	public String access_id;
    	public List<String> scope = new ArrayList<String>();
    }
}
