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
    public static TokenBuilder getInstance(String LinkID,String SecretKey) {
        if(_singleTone == null) {
            _singleTone = new TokenBuilder();
        }
        _singleTone._LinkID = LinkID;
        _singleTone._SecretKey = SecretKey;
        _singleTone._ServiceURL = DefaultServiceURL;
        
        return _singleTone;
    }
    
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
     * 
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
     * 
     * @param AccessID
     * @param forwardedIP
     * @return Token
     * @throws LinkhubException
     */
    public Token build(String AccessID, String forwardedIP) throws LinkhubException {
       
    	if(_recentServiceID == null || _recentServiceID.isEmpty()) throw new LinkhubException(-99999999,"서비스아이디가 입력되지 않았습니다.");
        
        HttpURLConnection httpURLConnection;
        String URI = "/" +  _recentServiceID + "/Token";
        
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

        TokenRequest request = new TokenRequest();
        request.access_id = AccessID;
        request.scope = _recentScope;
        
        String PostData = _gsonParser.toJson(request);
        byte[] btPostData = PostData.getBytes(Charset.forName("UTF-8"));
        
        String invokeTime = getTime();
        	               
        String signTarget = "POST\n";
        signTarget += md5Base64(btPostData)  + "\n";

        signTarget += invokeTime + "\n";
        if(forwardedIP != null && forwardedIP.isEmpty() == false) {
            signTarget += forwardedIP + "\n";
        }
        signTarget += APIVersion + "\n";
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
        
        DataOutputStream output = null;
        
        try {
            httpURLConnection.setRequestMethod("POST");
            httpURLConnection.setUseCaches(false);
            httpURLConnection.setDoOutput(true);
            
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
     * 
     * @param BearerToken
     * @param TOGO
     * @return
     * @throws LinkhubException
     */
    public String getPartnerURL(String BearerToken, String TOGO) throws LinkhubException {        
        HttpURLConnection httpURLConnection;
        String Result = "";
        InputStream input = null;
        
        String URI = "/" +  _recentServiceID + "/URL?TG=" + TOGO;
        
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
     * 
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
    	
        HttpURLConnection httpURLConnection;
        String URI = "/Time";
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
