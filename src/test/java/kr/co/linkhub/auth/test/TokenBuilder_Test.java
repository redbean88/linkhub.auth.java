package kr.co.linkhub.auth.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import kr.co.linkhub.auth.LinkhubException;
import kr.co.linkhub.auth.Token;
import kr.co.linkhub.auth.TokenBuilder;
import kr.co.linkhub.auth.test.config.TestConfig;
import kr.co.linkhub.auth.test.util.PrettyPrint;

import org.junit.Test;

public class TokenBuilder_Test {
	
	@Test
	public void Build_Success_Test() throws LinkhubException {
		
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(TestConfig.LinkID, TestConfig.SecretKey)
									.ServiceID("POPBILL")
									.addScope("member")
									.addScope("110");	//세금계산서
	
		Token token = tokenBuilder.build("1234567890");
//		tokenBuilder.setProxyIP("192.168.0.215");
//		tokenBuilder.setProxyPort(8081);
		PrettyPrint.setTitleNValue("서비스아이디", token.getServiceID());
		for (int i = 0; i < token.getScope().size(); i++) {
			PrettyPrint.setTitleNValue("스코프"+i, token.getScope().get(i));
		}
		PrettyPrint.setTitleNValue("접근아이디", "1234567890");
		PrettyPrint.setTitleNValue("토큰", token.toString());
		PrettyPrint.setTitleNValue("세션토큰", token.getSession_token());
		PrettyPrint.setTitleNValue("링크아이디", token.getLinkID());
		PrettyPrint.print();
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());
		
		token = tokenBuilder.build("1234567890");
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());


		PrettyPrint.setTitleNValue("서비스아이디", token.getServiceID());
		for (int i = 0; i < token.getScope().size(); i++) {
			PrettyPrint.setTitleNValue("스코프"+i, token.getScope().get(i));
		}
		PrettyPrint.setTitleNValue("접근아이디", "1234567890");
		PrettyPrint.setTitleNValue("토큰", token.toString());
		PrettyPrint.setTitleNValue("세션토큰", token.getSession_token());
		PrettyPrint.setTitleNValue("링크아이디", token.getLinkID());
		PrettyPrint.print();
	}
	
	/**
	 * JUSOLINK_DEV 검증필요
	 * @throws LinkhubException
	 */
	@Test
	public void Build_Partner_Success_Test() throws LinkhubException {
		
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(TestConfig.LinkID, TestConfig.SecretKey);
//									.ServiceID("JUSOLINK_DEV")
//									.addScope("200");
	
		Token token = tokenBuilder
								.ServiceID("POPBILL_TEST")
								.addScope("member")
								.addScope("110")	//세금계산서
								.build("1234567890");
//		tokenBuilder.setProxyIP("192.168.0.215");
//		tokenBuilder.setProxyPort(8081);
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());
		
		token = tokenBuilder.buildWithIP("123.123.123.123");	//????
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());
	}
	
	@Test(expected=LinkhubException.class)
	public void Build_Fail_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(TestConfig.LinkID, TestConfig.SecretKey);
		
		Token token = tokenBuilder
						.ServiceID("POPBIL_TEST")
						.addScope("member")
						.addScope("110")	//세금계산서
						.build("1231212312");
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());
	}

	@Test
	public void GetBalance_Success_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(TestConfig.LinkID, TestConfig.SecretKey);
		
		Token token = tokenBuilder
						.ServiceID("POPBILL_TEST")
						.addScope("member")
						.addScope("110")	//세금계산서
						.build("1234567890");
		
//		tokenBuilder.setProxyIP("192.168.0.215");
//		tokenBuilder.setProxyPort(8081);
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		double remainPoint = tokenBuilder.getBalance(token.getSession_token());
		
		assertTrue(remainPoint >= 0);
		
		PrettyPrint.setTitleNValue("잔여포인트", String.valueOf(remainPoint));
		PrettyPrint.print();
		
	}
	
	@Test
	public void GetPartnerBalance_Success_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(TestConfig.LinkID, TestConfig.SecretKey);
		
		Token token = tokenBuilder
							.ServiceID("POPBILL_TEST")
							.addScope("member")
							.addScope("110")	//세금계산서
							.build("1234567890");
		
//		tokenBuilder.setProxyIP("192.168.0.215");
//		tokenBuilder.setProxyPort(8081);
		
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		double remainPoint = tokenBuilder.getPartnerBalance(token.getSession_token());
		
		assertTrue(remainPoint >= 0);
		
		PrettyPrint.setTitleNValue("파트너 잔여포인트 " ,String.valueOf(remainPoint));
		PrettyPrint.print();
		
	}
	
	@Test
	public void GetTime_Success_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(TestConfig.LinkID, TestConfig.SecretKey);
		
		List<String> scopes = new ArrayList<String>();
		scopes.add("member");
		
		Token token = tokenBuilder
							.ServiceID("POPBILL_TEST")
							.addScope("member")
							.addScope("110")	//세금계산서
							.build("1234567890");
		
//		tokenBuilder.setProxyIP("192.168.0.215");
//		tokenBuilder.setProxyPort(8081);
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		String UTCTime = tokenBuilder.getTime();
		
		assertNotNull(UTCTime);
		
		PrettyPrint.setTitleNValue("Response UTCTime " ,UTCTime);
		PrettyPrint.print();
		
	}
	
	@Test
	public void GetLocalTime_Success_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(TestConfig.LinkID, TestConfig.SecretKey)
												.useLocalTimeYN(true);
				
		String LocalTime = tokenBuilder.getTime();
		
		assertNotNull(LocalTime);
		
		PrettyPrint.setTitleNValue("Response LocalTime",LocalTime);
			
	}

	@Test
	public void GetPartnerURL_Success_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(TestConfig.LinkID, TestConfig.SecretKey);
		
		Token token = tokenBuilder
						.ServiceID("POPBILL_TEST")
						.addScope("member")	
						.addScope("110")	//세금계산서
						.build("1234567890");
		
//		tokenBuilder.setProxyIP("192.168.0.215");
//		tokenBuilder.setProxyPort(8081);
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		String url = tokenBuilder.getPartnerURL(token.getSession_token(), "LOGIN");
		
		assertNotNull(url);
		
		PrettyPrint.setTitleNValue("주소",url);
		PrettyPrint.print();
		
	}
	
	
	/*
	 * [문제] 예금 만기 금액을 구하는 문제.
 
		예금은 복리입니다. 예를 들어 10% 이율의 예금에 가입 100,000 만원 예치시, 1년 후에는 110,000원, 2년 후에는 121,000원입니다. 
		본 예금은 이벤트가 있어서 예금을 든 후 부터 3의 배수인 해가 될 때에는 해당  연차를 5로 나눈 나머지 만큼 (예를 들어 12년 에는 2%, 3년에는 3%) 더 이율이 추가되어 지급됩니다.
		 
		위의 조건을 만족하는 함수를 작성해 주시면 되며, 함수는 재귀적(recursive)로 작성하시기 바랍니다.
		 
		함수 입력값: 원금, 이율(%), 기간(년)
		출력값: 만기시 원금+이자의 합
	 */
	@Test
	public void GetInterest_TEST()
	{
		for(int year = 1 ; year <= 20; year++)
			PrettyPrint.setTitleNValue("예금"+year,String.valueOf(CalculateInterest(100000,10,year)));
			PrettyPrint.print();
	}

	public long CalculateInterest(long Principal , int Rate , int year)
	{
		return (long)((year > 1 ?  this.CalculateInterest(Principal,Rate,year - 1) : Principal) * ( 1f + calculatedRatePercent(Rate,year)));
	}
   
	public float calculatedRatePercent(int Rate , int Year) {
		return (float)(Rate + (Year % 3 == 0 ? Year % 5 : 0 )) / 100 ;
	}
}
