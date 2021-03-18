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

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.TimeZone;
import java.util.zip.GZIPInputStream;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.google.gson.Gson;

/**
 * Linkhub TokenBuilder class.
 * @author KimSeongjun
 * @see http://www.linkhub.co.kr
 * @version 1.2.1
 * 
 * Update Log
 * (2017/08/25) - GetPartnerURL API added
 */
public class TokenBuilder {

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static final String APIVersion = "1.0";
    private static final String DefaultServiceURL = "https://auth.linkhub.co.kr";
    
    private String _ServiceURL;
    private String _ProxyIP;
    private Integer _ProxyPort;
    private String _LinkID;
    private String _SecretKey;
    private Gson _gsonParser;
    
    private String _recentServiceID;
    private List<String> _recentScope;
    private boolean _useLocalTime;
    
    /**
     * Gson 인스턴스 생성 
     */
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
    @Deprecated
    public static TokenBuilder getInstance(String LinkID,String SecretKey) { //멀티쓰레드?? 비추된 이유를 확인해 볼것
        if(_singleTone == null) {
            _singleTone = new TokenBuilder();
        }
        _singleTone._LinkID = LinkID;
        _singleTone._SecretKey = SecretKey;
        _singleTone._ServiceURL = DefaultServiceURL;
        
        return _singleTone;
    }
    
    /**
     * 신규 인스턴스 생성
     * @param LinkID
     * @param SecretKey
     * @return
     */
    public static TokenBuilder newInstance(String LinkID,String SecretKey) {
        
        TokenBuilder _singleTone = new TokenBuilder();
    
        _singleTone._LinkID = LinkID;
        _singleTone._SecretKey = SecretKey;
        _singleTone._ServiceURL = DefaultServiceURL;
        
        return _singleTone;
    }
    
    /**
     * @param Target 서비스 URL를 변경합니다. Proxy환경에서 사용합니다.
     */
    public void setServiceURL(String URL) {
        this._ServiceURL = URL;
    }
    /**
     * 서비스아이디 설정
     * @param ServiceID 서비스아이디
     * @return this for method chaining.
     */
    public TokenBuilder ServiceID(String ServiceID) {
        this._recentServiceID = ServiceID;
        return this;
    }
    
    public void setProxyIP(String IP) {
    	this._ProxyIP = IP;
    }
    
    public void setProxyPort(int PORT) {
    	this._ProxyPort = PORT;
    }
    /**
     * @note
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
     * LocalTime 설정
     * * LocalTime이란 클라이언트 시스템시간을 의미
     *  
     * @param useLocalTimeYN 로컬타임 여부
     * @return this for method chaining.
     */
    public TokenBuilder useLocalTimeYN(boolean useLocalTimeYN) {
    	this._useLocalTime = useLocalTimeYN;
    	return this;
    }
    
    /**
     * 
     * @return Token
     * @throws LinkhubException
     */
    public Token build() throws LinkhubException {
        return build(null,null);
    }
    
    /**
     * 
     * @return Token
     * @param forwardedIP
     * @throws LinkhubException
     */
    public Token buildWithIP(String ForwardedIP) throws LinkhubException {
        return build(null,ForwardedIP);
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
     * <pre>토큰 생성</pre>
     * <pre>본 메서드는 인증서버와 POST 통신을 하여 Token을 생성하는 메서드 입니다</pre>
	 * <pre>{@link java.net.HttpURLConnection HttpURLConnection} 인스턴스 생성합니다</pre>
	 * <pre>인증 관련 정보 설정합니다</pre>
	 * <pre>연동 기본값 설정합니다</pre>
	 * <pre>요청 데이터 인코딩 및 서명 작업을 진행합니다</pre>
	 * <pre>결과 데이터 반환합니다</pre>
	 * <pre>자세한 내용은 아래 내용을 참고해 주세요.</pre>
     * <pre>AccessID, forwardedIP 두개의 parameter는 null을 허용, 다음의 4가지 패턴으로 처리됨</pre>
     * <pre>	1. AccessID이 존재하고, forwardedIP이 null인경우</pre>
     * <pre>	2. forwardedIP이 존재하고, AccessID이 null인경우(예외발생)</pre>
     * <pre>		1. {@link kr.co.linkhub.auth.LinkhubException LinkhubException} 반환 (사용자 식별정보가 입력되지 않았습니다.)</pre>
     * <pre>	3. 모두 존재하는 경우(예외발생)</pre>
     * <pre>		1. forwardedIP값이 허용값인지 확인 필요, 비허용의 경우 {@link kr.co.linkhub.auth.LinkhubException LinkhubException} 반환 (링크아이디에 사용 가능한 아이피주소가 아닙니다.)</pre>
     * <pre>	4. 모두 null 인 경우(예외발생)</pre>
     * <pre>		1. {@link kr.co.linkhub.auth.LinkhubException LinkhubException} 반환 (사용자 식별정보가 입력되지 않았습니다.)</pre>
     * <pre>1. {@link #_recentServiceID _recentServiceID} 값이 null 이거나 길이가 0인 경우, {@link kr.co.linkhub.auth.LinkhubException#LinkhubException(long code, String Message) LinkhubException} 반환("서비스아이디가 입력되지 않았습니다.")</pre>
     * <pre>2. {@link java.net.HttpURLConnection HttpURLConnection} 인스턴스 생성</pre>
     * <pre>	1. _ProxyIP와 _ProxyPort가 null이 아닌 경우, 프록시 기반 HttpConnection 생성</pre>
     * <pre>	2. _ProxyIP와 _ProxyPort가 null인 경우,uri를 이용한 HttpConnection 생성</pre>
     * <pre>3. {@link #_useLocalTime _useLocalTime} 값에 따라 {@link #getTime() getTime} 메소드를 이용하여 현재시간을 문자열을 획득 (eg.2021-03-15T04:33:19Z)</pre>
     * <pre>	1. {@link #_useLocalTime _useLocalTime} 이 True인 경우, 클라이언트 시스템시간을 반환</pre>
     * <pre>	2. {@link #_useLocalTime _useLocalTime} 이 False인 경우, {@link #DefaultServiceURL DefaultServiceURL} 서버의 시간을 반환</pre>
     * <pre>4.  API 서버와 통신을 위한 설정값을 header에 할당</pre>
     * <pre>	1. x-lh-date : API서버에서 해당 값을 기준으로 유효기간을 확인(현재 시간)</pre>
	 * <pre>	2. x-lh-version </pre>
	 * <pre>	3. contentType 할당( 기본값 : application/json; charset=utf8 )</pre>
	 * <pre>	4. RequestMethod를 POST로 할당</pre>
	 * <pre> 	5. 캐시저장값 미사용처리(setUseCaches(false))</pre>
	 * <pre> 	6. Post방식 사용을 위한 출력 스트림 사용 가능하도록 지정 (setDoOutput(true))</pre>
	 * <pre>5. PostData 생성</pre>
	 * <pre>	1. {@link kr.co.linkhub.auth.TokenBuilder.TokenRequest tokenRequest} 생성</pre>
	 * <pre>	2. {@link kr.co.linkhub.auth.TokenBuilder.TokenRequest tokenRequest} 에 access_id , scope에 각각 AccessID, {@link #_recentScope _recentScope} 할당</pre>
	 * <pre>	3. {@link kr.co.linkhub.auth.TokenBuilder.TokenRequest tokenRequest} 를 json형식으로 파싱후 바이너리 데이터로 변경 (이하 바이너리 데이터)</pre>
	 * <pre>	4. http메소드(post), 인코딩된 바이너리 데이터 , 생성시간 , APIversion, uri 값을 이용하여 본문 생성(singTarget)</pre>
	 * <pre>		* 인코딩된 바이너리 데이터는 바이너리 데이터와 {@link #md5Base64(byte[]) md5Base64} 함수를 이용하여 생성</pre>
	 * <pre>		* signTarget에 forwardedIP가 null이 아닌경우, forwardedIP 할당</pre>
	 * <pre>	5. 위변조 검증을 위해, {@link #HMacSha1(byte[], byte[]) HMacSha1} 함수를 이용하여 서명(Signature)을 생성</pre>
	 * <pre>		* {@link #HMacSha1(byte[], byte[]) HMacSha1} : 키는 시크릿키며, 데이터는 본문</pre>
	 * <pre>6. forwardedIP가 null이 아닌경우, "x-lh-forwarded"에 forwardedIP 할당</pre>
	 * <pre>7. 인증값 할당</pre>
	 * <pre>	1. "LINKHUB" + LINKID + 서명  을 합쳐 "Authorization"에 값을 할당 </pre>
	 * <pre>	2. "Content-Length"에 바이너리데이터의 길이 값을 할당 </pre>
	 * <pre>9. 전송 및 회신</pre>
	 * <pre>	1. getContentEncoding이 gzip일 경우, {@link #fromGzipStream(InputStream) fromGzipStream}메소드 호출</pre>
	 * <pre>	2. getContentEncoding이 gzip이 아닐 경우, {@link #fromStream(InputStream) fromStream} 메소드 호출</pre>
	 * <pre>10. 회신 결과를 {@link com.google.gson.Gson#fromJson(String, Class) fromJsonString} 함수를 이용 json 데이터를 두번째 argument 타입으로 파싱하여 반환</pre>
	 *
     * @param AccessID
     * @param forwardedIP
     * @return Token
     * @throws LinkhubException
     */
    public Token build(String AccessID, String forwardedIP) throws LinkhubException {
       
    	//1
    	if(_recentServiceID == null || _recentServiceID.isEmpty()) throw new LinkhubException(-99999999,"서비스아이디가 입력되지 않았습니다.");
        
    	//2
        HttpURLConnection httpURLConnection = null;
        String URI = "/" +  _recentServiceID + "/Token";
        
        httpURLConnection = makeHttpUrlConnection(httpURLConnection, URI);
        
        //3
        String invokeTime = getTime();
        
        //4
        httpURLConnection.setRequestProperty("x-lh-date".toLowerCase(), invokeTime);
        httpURLConnection.setRequestProperty("x-lh-version".toLowerCase(), APIVersion);
        httpURLConnection.setRequestProperty("Content-Type","application/json; charset=utf8");
        
        try {
        	httpURLConnection.setRequestMethod("POST");
        } catch (ProtocolException e2) {
        	e2.printStackTrace();
        }
        httpURLConnection.setUseCaches(false);
        httpURLConnection.setDoOutput(true);
        
        //5
        TokenRequest request = new TokenRequest();
        request.access_id = AccessID;
        request.scope = _recentScope;
        
        String PostData = _gsonParser.toJson(request);
        byte[] btPostData = PostData.getBytes(Charset.forName("UTF-8"));
        
        	               
        String signTarget = "POST\n";
        signTarget += md5Base64(btPostData)  + "\n";

        signTarget += invokeTime + "\n";
        if(forwardedIP != null && forwardedIP.isEmpty() == false) {
            signTarget += forwardedIP + "\n";
        }
        signTarget += APIVersion + "\n";
        signTarget += URI;
                
        byte[] bytes = signTarget.getBytes(Charset.forName("UTF-8"));
		byte[] base64Decode = base64Decode(getSecretKey());
		byte[] hMacSha1 = HMacSha1(base64Decode, bytes);
		String Signature = base64Encode(hMacSha1);
		//6
        if(forwardedIP != null && forwardedIP.isEmpty() == false) {	//왜 두번이나 필요한가?
            httpURLConnection.setRequestProperty("x-lh-forwarded".toLowerCase(), forwardedIP);
        }
        //7
        httpURLConnection.setRequestProperty("Authorization","LINKHUB "+ getLinkID() + " " + Signature);
        httpURLConnection.setRequestProperty("Content-Length",String.valueOf(btPostData.length));

        //8
        DataOutputStream output = null;
        try {
            output = new DataOutputStream(httpURLConnection.getOutputStream());
            output.write(btPostData);
            output.flush();
        } catch (Exception e) {
            throw new LinkhubException(-99999999, "Fail to POST data to Server.",e);
        } finally {            
            if (output != null) {
                try {
                    output.close();
                } catch (IOException e1) {
                    throw new LinkhubException(-99999999, 
                            "Linkhub TokenBuilder build func output stream close exception.",e1);
                }
            }
        }
        
        String Result = "";
        InputStream input = null;
        
        try {
            input = httpURLConnection.getInputStream();
            
            if (null != httpURLConnection.getContentEncoding() && httpURLConnection.getContentEncoding().equals("gzip")) {
                Result = fromGzipStream(input);
            } else {
                Result = fromStream(input);
            }
            
        } catch (IOException e) {
            Error error = null;
            InputStream is = null;
            
            try {
                is = httpURLConnection.getErrorStream();
                Result = fromStream(is);
                
                error = _gsonParser.fromJson(Result, Error.class);
            }
            catch (Exception E) {
                
            } finally {
                if (is != null) {
                    try {
                        is.close();
                    } catch (IOException e3) {
                        throw new LinkhubException(-99999999, 
                                "Linkhub TokenBuilder build func Error inputstream close exception.",e3);
                    }
                }
            }
            
            if(error == null)
                throw new LinkhubException(-99999999, "Fail to receive data from Server.",e);
            else
                throw new LinkhubException(error.code,error.message);
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e1) {
                    throw new LinkhubException(-99999999, 
                            "Linkhub TokenBuilder build func input stream close exception.",e1);
                }
            }
        }
        //9
        return _gsonParser.fromJson(Result, Token.class);
    
    }
    
    /**
     * 잔액 조회
     * <pre>본 메서드는 인증서버와 GET 통신을 하여 사용자 잔액을 조회하는 메서드 입니다</pre>
	 * <pre>{@link java.net.HttpURLConnection HttpURLConnection} 인스턴스 생성합니다</pre>
	 * <pre>인증 관련 정보 설정합니다</pre>
	 * <pre>결과 데이터 반환합니다</pre>
	 * <pre>자세한 내용은 아래 내용을 참고해 주세요.</pre>
     * <pre>1. BearerToken 값이 null 이거나 길이가 0 인 경우, {@link kr.co.linkhub.auth.LinkhubException LinkhubException} 반환 ("BearerToken이 입력되지 않았습니다.")</pre>
     * <pre>2. {@link #_recentServiceID _recentServiceID} 값이 null 이거나 길이가 0 인 경우, {@link kr.co.linkhub.auth.LinkhubException LinkhubException} 반환 ("서비스아이디가 입력되지 않았습니다.")</pre>
     * <pre>3. {@link java.net.HttpURLConnection HttpURLConnection} 인스턴스 생성</pre>
     * <pre>	1. _ProxyIP와 _ProxyPort가 null이 아닌 경우, 프록시 기반 HttpConnection 생성</pre>
     * <pre>	2. _ProxyIP와 _ProxyPort가 null인 경우,uri를 이용한 HttpConnection 생성</pre>
     * <pre>4. 인증서버와 통신을 위한 설정값을 header에 할당</pre>
     * <pre>	1. Bearer + BearerToken 을 합쳐 Authorization에 값을 할당</pre>
	 * <pre>5. 회신</pre>
	 * <pre>	1. getContentEncoding이 gzip일 경우, {@link #fromGzipStream(InputStream) fromGzipStream} 메소드 호출</pre>
	 * <pre>	2. getContentEncoding이 gzip이 아닐 경우, {@link #fromStream(InputStream) fromStream} 메소드 호출</pre>
	 * <pre>6. 회신 결과를  {@link com.google.gson.Gson#fromJson(String, Class) fromJsonString} 함수를 이용 json 데이터를 두번째 argument 타입으로 파싱후 {@link 
kr.co.linkhub.auth.TokenBuilder.PointResult#getRemainPoint() getRemainPoint} 메소드값 반환(double)</pre>
     * @param BearerToken Token.getSession_Token()
     * @return remainPoint
     * @throws LinkhubException
     */
    public double getBalance(String BearerToken) throws LinkhubException {
        if(BearerToken == null || BearerToken.isEmpty()) throw new LinkhubException(-99999999,"BearerToken이 입력되지 않았습니다.");
        if(_recentServiceID == null || _recentServiceID.isEmpty()) throw new LinkhubException(-99999999,"서비스아이디가 입력되지 않았습니다.");
        
        HttpURLConnection httpURLConnection = null;
        String URI = "/" +  _recentServiceID + "/Point";
        httpURLConnection = makeHttpUrlConnection(httpURLConnection, URI);

        httpURLConnection.setRequestProperty("Authorization","Bearer " + BearerToken);
        
        String Result = "";
        InputStream input = null;
        
        try {
            input = httpURLConnection.getInputStream();
                
            if (null != httpURLConnection.getContentEncoding() && httpURLConnection.getContentEncoding().equals("gzip")) {
                Result = fromGzipStream(input);
            } else {
                Result = fromStream(input);
            }
            
        } catch (IOException e) {
            
            Error error = null;
            InputStream is = null;
            
            try    {
                is = httpURLConnection.getErrorStream();
                Result = fromStream(is);                
                error = _gsonParser.fromJson(Result, Error.class);
            } catch(Exception E) {
                
            } finally {
                if (is != null){
                    try {
                        is.close();
                    } catch (IOException e1) {
                        throw new LinkhubException(-99999999, 
                                "Linkhub getBalance func Error inputstream close exception.",e);
                    }
                }
            }
            
            if (error == null)
                throw new LinkhubException(-99999999, "Fail to receive data from Server.",e);
            else
                throw new LinkhubException(error.code,error.message);
        } finally {
            if (input != null){
                try {
                    input.close();
                } catch (IOException e) {
                    throw new LinkhubException(-99999999, 
                            "Linkhub getBalance func inputstream close exception.",e);
                }
            }
        }
        
        return _gsonParser.fromJson(Result, PointResult.class).getRemainPoint();
    }

	private HttpURLConnection makeHttpUrlConnection(HttpURLConnection httpURLConnection, String URI)
			throws LinkhubException {
		try {
            URL url = new URL(_ServiceURL + URI);
            
            if(_ProxyIP != null && _ProxyPort != null) {
            	Proxy prx =  new Proxy(Type.HTTP, new InetSocketAddress(_ProxyIP, _ProxyPort));
            	httpURLConnection = (HttpURLConnection) url.openConnection(prx);
            } else {
            	httpURLConnection = (HttpURLConnection) url.openConnection();
            }
            
        } catch (Exception e) {
            throw new LinkhubException(-99999999, "링크허브 서버 접속 실패",e);
        }
		return httpURLConnection;
	}
    
    /**
     * 잔액 조회
     * <pre>본 메서드는 인증서버와 GET 통신을 하여 사용자 잔액을 조회하는 메서드 입니다</pre>
	 * <pre>{@link java.net.HttpURLConnection HttpURLConnection} 인스턴스 생성합니다</pre>
	 * <pre>인증 관련 정보 설정합니다</pre>
	 * <pre>결과 데이터 반환합니다</pre>
	 * <pre>자세한 내용은 아래 내용을 참고해 주세요.</pre>
     * <pre>1. BearerToken 값이 null 이거나 길이가 0 인 경우, {@link kr.co.linkhub.auth.LinkhubException LinkhubException} 반환 ("BearerToken이 입력되지 않았습니다.")</pre>
     * <pre>2. {@link #_recentServiceID _recentServiceID} 값이 null 이거나 길이가 0 인 경우, {@link kr.co.linkhub.auth.LinkhubException LinkhubException} 반환 ("서비스아이디가 입력되지 않았습니다.")</pre>
     * <pre>3. {@link java.net.HttpURLConnection HttpURLConnection} 인스턴스 생성</pre>
     * <pre>	1. _ProxyIP와 _ProxyPort가 null이 아닌 경우, 프록시 기반 HttpConnection 생성</pre>
     * <pre>	2. _ProxyIP와 _ProxyPort가 null인 경우,uri를 이용한 HttpConnection 생성</pre>
     * <pre>4. 인증서버와 통신을 위한 설정값을 header에 할당</pre>
     * <pre>	1. Bearer + BearerToken 을 합쳐 Authorization에 값을 할당</pre>
	 * <pre>5. 회신</pre>
	 * <pre>	1. getContentEncoding이 gzip일 경우, {@link #fromGzipStream(InputStream) fromGzipStream} 메소드 호출</pre>
	 * <pre>	2. getContentEncoding이 gzip이 아닐 경우, {@link #fromStream(InputStream) fromStream} 메소드 호출</pre>
	 * <pre>6. 회신 결과를  {@link com.google.gson.Gson#fromJson(String, Class) fromJsonString} 함수를 이용 json 데이터를 두번째 argument 타입으로 파싱후 {@link 
kr.co.linkhub.auth.TokenBuilder.PointResult#getRemainPoint() getRemainPoint} 메소드값 반환(double)</pre>
     * @param BearerToken Token.getSession_Token()
     * @return remainPoint
     * @throws LinkhubException
     */
    public double getPartnerBalance(String BearerToken) throws LinkhubException {
        if(BearerToken == null || BearerToken.isEmpty()) throw new LinkhubException(-99999999,"BearerToken이 입력되지 않았습니다.");
        if(_recentServiceID == null || _recentServiceID.isEmpty()) throw new LinkhubException(-99999999,"서비스아이디가 입력되지 않았습니다.");
        
        HttpURLConnection httpURLConnection = null;
        String URI = "/" +  _recentServiceID + "/PartnerPoint";
        httpURLConnection = makeHttpUrlConnection(httpURLConnection, URI);

        httpURLConnection.setRequestProperty("Authorization","Bearer " + BearerToken);
        
        String Result = "";
        InputStream input = null;
        
        try {
            input = httpURLConnection.getInputStream();
            if (null != httpURLConnection.getContentEncoding() && httpURLConnection.getContentEncoding().equals("gzip")) {
                Result = fromGzipStream(input);
            } else {
                Result = fromStream(input);
            }
        } catch (IOException e) {
            
            Error error = null;
            InputStream is = null;
            
            try    {
                is = httpURLConnection.getErrorStream();
                Result = fromStream(is);
                error = _gsonParser.fromJson(Result, Error.class);
            } catch(Exception E) {
                
            } finally {
                if (is != null){
                    try {
                        is.close();
                    } catch (IOException e1) {
                        throw new LinkhubException(-99999999, 
                                "Linkhub getPartnerBalance func Error inputstream close exception.",e);
                    }
                }
            }
            
            if (error == null)
                throw new LinkhubException(-99999999, "Fail to receive data from Server.",e);
            else
                throw new LinkhubException(error.code,error.message);
        } finally {
            if (input != null){
                try {
                    input.close();
                } catch (IOException e) {
                    throw new LinkhubException(-99999999, 
                            "Linkhub getPartnerBalance func input stream close exception.",e);
                }
            }
        }
        
        return _gsonParser.fromJson(Result, PointResult.class).getRemainPoint();
    }
    
    
    /**
     * 파트너조회(BearerToken , "페이지 패턴 ['LOGIN']")  // 대소문자 처리 확인 필요
     * <pre>본 메서드는 인증서버와 GET 통신을 하여 사용자 잔액을 조회하는 메서드 입니다</pre>
	 * <pre>{@link java.net.HttpURLConnection HttpURLConnection} 인스턴스 생성합니다</pre>
	 * <pre>인증 관련 정보 설정합니다</pre>
	 * <pre>결과 데이터 반환합니다</pre>
	 * <pre>자세한 내용은 아래 내용을 참고해 주세요.</pre>
	 * 
	 * <pre>1. BearerToken 값이 null 이거나 길이가 0 인 경우, {@link kr.co.linkhub.auth.LinkhubException LinkhubException} 반환 ("BearerToken이 입력되지 않았습니다.")</pre>
     * <pre>2. {@link java.net.HttpURLConnection HttpURLConnection} 인스턴스 생성</pre>
     * <pre>	1. _ProxyIP와 _ProxyPort가 null이 아닌 경우, 프록시 기반 HttpConnection 생성</pre>
     * <pre>	2. _ProxyIP와 _ProxyPort가 null인 경우,uri를 이용한 HttpConnection 생성</pre>
     * <pre>3. 인증서버와 통신을 위한 설정값을 header에 할당</pre>
     * <pre>	1. Bearer + BearerToken 을 합쳐 Authorization에 값을 할당</pre>
	 * <pre>4. 회신</pre>
	 * <pre>	1. getContentEncoding이 gzip일 경우, {@link #fromGzipStream(InputStream) fromGzipStream} 메소드 호출</pre>
	 * <pre>	2. getContentEncoding이 gzip이 아닐 경우, {@link #fromStream(InputStream) fromStream} 메소드 호출</pre>
	 * <pre>5. 회신 결과를  {@link com.google.gson.Gson#fromJson(String, Class) fromJsonString} 함수를 이용 json 데이터를 두번째 argument 타입으로 파싱후 {@link kr.co.linkhub.auth.TokenBuilder.URLResult#getURL() getURL} 메소드 리턴값 반환(string)</pre>
     * @param BearerToken
     * @param TOGO
     * @return
     * @throws LinkhubException
     */
    public String getPartnerURL(String BearerToken, String TOGO) throws LinkhubException {        
        HttpURLConnection httpURLConnection = null;
        String Result = "";
        InputStream input = null;
        
        String URI = "/" +  _recentServiceID + "/URL?TG=" + TOGO;
        
        httpURLConnection = makeHttpUrlConnection(httpURLConnection, URI);
        
        httpURLConnection.setRequestProperty("Authorization","Bearer " + BearerToken);
        
        try {
            input = httpURLConnection.getInputStream();
            
            if (null != httpURLConnection.getContentEncoding() && httpURLConnection.getContentEncoding().equals("gzip")) {
                Result = fromGzipStream(input);
            } else {
                Result = fromStream(input);
            }
        } catch (IOException e) {
            Error error = null;
            InputStream is = null;

            try    {
                is = httpURLConnection.getErrorStream();
                Result = fromStream(is);
                error = _gsonParser.fromJson(Result, Error.class);
            }
            catch(Exception E) {
                
            } finally {
                if (is != null){
                    try {
                        is.close();
                    } catch (IOException e1) {
                        throw new LinkhubException(-99999999, 
                                "Linkhub getPartnerURL func inputstream close exception.",e);
                    }
                }
            }
            
            if(error == null)
                throw new LinkhubException(-99999999, "Fail to receive getPartnerURL from Server.",e);
            else
                throw new LinkhubException(error.code,error.message);
        } finally {
            if (input != null){
                try {
                    input.close();
                } catch (IOException e) {
                    throw new LinkhubException(-99999999, 
                            "Linkhub getPartnerURL func inputstream close exception.",e);
                }
            }
        }
        
        return _gsonParser.fromJson(Result, URLResult.class).getURL();
    }
    
    /**
     * <pre>1. _useLocalTime 값이 True일 경우, 클라이언트 시스템 시간을 반환</pre>
     * <pre>2. _useLocalTime 값이 False일 경우</pre>
     * <pre>	1. httpURLConnection 생성</pre>
     * <pre>	2. /Time Url 호출</pre>
     * <pre>	3. 반환값이 gzip 타입일 경우, fromGzipStream() 아니면 fromStream()</pre>
     * @return API Server UTCTime
     * @throws LinkhubException
     */
    public String getTime() throws LinkhubException {    
    	
    	if(_useLocalTime) {
        	
        	SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        	format.setTimeZone(TimeZone.getTimeZone("UTC"));
        	        	
        	String localTime = format.format(System.currentTimeMillis());
        	
        	return localTime;
    	}
    	
        HttpURLConnection httpURLConnection = null;
        String URI = "/Time";
        httpURLConnection = makeHttpUrlConnection(httpURLConnection, URI);
        
        String Result = "";
        InputStream input = null;
        
        try {
            input = httpURLConnection.getInputStream();
            if (null != httpURLConnection.getContentEncoding() && httpURLConnection.getContentEncoding().equals("gzip")) {
                Result = fromGzipStream(input);
            } else {
                Result = fromStream(input);
            }
            
        } catch (IOException e) {
            
            Error error = null;
            InputStream is = null;
            try    {
                is = httpURLConnection.getErrorStream();
                Result = fromStream(is);
                error = _gsonParser.fromJson(Result, Error.class);
            }
            catch(Exception E) {
                
            } finally {
                if (is != null){
                    try {
                        is.close();
                    } catch (IOException e1) {
                        throw new LinkhubException(-99999999, 
                                "Linkhub getTime func inputstream close exception.",e);
                    }
                }
            }
            
            if(error == null)
                throw new LinkhubException(-99999999, "Fail to receive UTC Time from Server.",e);
            else
                throw new LinkhubException(error.code,error.message);
        } finally {
            if (input != null){
                try {
                    input.close();
                } catch (IOException e) {
                    throw new LinkhubException(-99999999, 
                            "Linkhub getTime func inputstream close exception.",e);
                }
            }
            
        }
        
        return (String) Result;
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
        } catch (NoSuchAlgorithmException e) {    }
        
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
    
    private static String fromStream(InputStream input) throws LinkhubException {
        InputStreamReader is = null;
        BufferedReader br = null;
        StringBuilder sb = null;
        
        try {
            is = new InputStreamReader(input,Charset.forName("UTF-8"));
            sb = new StringBuilder();
            br = new BufferedReader(is);
            
            String read = br.readLine();

            while(read != null) {
                sb.append(read);
                read = br.readLine();
            }
        } catch (IOException e){
            
        } finally {
            try {
                if (br != null) br.close();
                if (is != null) is.close();
            } catch (IOException e){
                throw new LinkhubException(-99999999, 
                        "Linkhub fromStream func inputStream close exception.",e);
            }
        }
        
        return sb.toString();
    }
    
    private static String fromGzipStream(InputStream input) throws LinkhubException {
        GZIPInputStream zipReader = null;
        InputStreamReader is = null;        
        BufferedReader br = null;
        StringBuilder sb = null;
        
        try {
            zipReader = new GZIPInputStream(input);
            is = new InputStreamReader(zipReader, "UTF-8");
            br = new BufferedReader(is);
            sb = new StringBuilder();
    
            String read = br.readLine();
    
            while (read != null) {
                sb.append(read);
                read = br.readLine();
            }
        } catch (IOException e) {
            throw new LinkhubException(-99999999, 
                    "Linkhub fromGzipStream func Exception", e);
        } finally {
            try {
                if (br != null) br.close();
                if (is != null) is.close();
                if (zipReader != null) zipReader.close();
            } catch (IOException e) {
                throw new LinkhubException(-99999999,
                    "Linkhub fromGzipStream func finally close Exception", e);
            }
        }
        
        return sb.toString();
    }    
    
    class PointResult {
        private double remainPoint;

        public double getRemainPoint() {
            return remainPoint;
        }
    }
    
    class URLResult {
        private String url;
        
        public String getURL(){
            return url;
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
