package kr.co.linkhub.auth.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import kr.co.linkhub.auth.LinkhubException;
import kr.co.linkhub.auth.Token;
import kr.co.linkhub.auth.TokenBuilder;

import org.junit.Test;

public class TokenBuilder_Test {
	
	private final String LinkID = "TESTER";
	private final String SecretKey = "SwWxqU+0TErBXy/9TVjIPEnI0VTUMMSQZtJf3Ed8q3I=";
	
	@Test
	public void Build_Success_Test() throws LinkhubException {
		
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(LinkID, SecretKey)
									.ServiceID("POPBILL")
									.addScope("member")
									.addScope("110");
	
		Token token = tokenBuilder.build("1234567890");
		tokenBuilder.setProxyIP("192.168.0.215");
		tokenBuilder.setProxyPort(8081);
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());
		
		token = tokenBuilder.build("1234567890");
		
		assertNotNull(token);
		
		System.out.println(token.getSession_token());
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());
	}
	
	@Test
	public void Build_Partner_Success_Test() throws LinkhubException {
		
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(LinkID, SecretKey)
									.ServiceID("JUSOLINK_DEV")
									.addScope("200");
	
		Token token = tokenBuilder.build();
		tokenBuilder.setProxyIP("192.168.0.215");
		tokenBuilder.setProxyPort(8081);
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());
		
		token = tokenBuilder.buildWithIP("123.123.123.123");
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());
	}
	
	@Test(expected=LinkhubException.class)
	public void Build_Fail_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(LinkID, SecretKey);
		
		Token token = tokenBuilder
						.ServiceID("POPBIL_TEST")
						.addScope("member")
						.addScope("110")
						.build("1231212312");
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());
	}

	@Test
	public void GetBalance_Success_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(LinkID, SecretKey);
		
		Token token = tokenBuilder
						.ServiceID("POPBILL_TEST")
						.addScope("member")
						.addScope("110")
						.build("1234567890");
		
		tokenBuilder.setProxyIP("192.168.0.215");
		tokenBuilder.setProxyPort(8081);
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		double remainPoint = tokenBuilder.getBalance(token.getSession_token());
		
		assertTrue(remainPoint >= 0);
		
		System.out.println("잔여포인트 : " + String.valueOf(remainPoint));
		
	}
	
	@Test
	public void GetPartnerBalance_Success_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(LinkID, SecretKey);
		
		List<String> scopes = new ArrayList<String>();
		scopes.add("member");
		
		Token token = tokenBuilder
							.ServiceID("POPBILL_TEST")
							.addScope("member")
							.addScope("110")
							.build("1234567890");
		
		tokenBuilder.setProxyIP("192.168.0.215");
		tokenBuilder.setProxyPort(8081);
		
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		double remainPoint = tokenBuilder.getPartnerBalance(token.getSession_token());
		
		assertTrue(remainPoint >= 0);
		
		System.out.println("파트너 잔여포인트 : " + String.valueOf(remainPoint));
		
	}
	
	@Test
	public void GetTime_Success_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(LinkID, SecretKey);
		
		List<String> scopes = new ArrayList<String>();
		scopes.add("member");
		
		Token token = tokenBuilder
							.ServiceID("POPBILL_TEST")
							.addScope("member")
							.addScope("110")
							.build("1234567890");
		
		tokenBuilder.setProxyIP("192.168.0.215");
		tokenBuilder.setProxyPort(8081);
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		String UTCTime = tokenBuilder.getTime();
		
		assertNotNull(UTCTime);
		
		System.out.println("Response UTCTime : " + UTCTime);
		
	}

	@Test
	public void GetPartnerURL_Success_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.newInstance(LinkID, SecretKey);
		
		Token token = tokenBuilder
						.ServiceID("POPBILL_TEST")
						.addScope("member")
						.addScope("110")
						.build("1234567890");
		
		tokenBuilder.setProxyIP("192.168.0.215");
		tokenBuilder.setProxyPort(8081);
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		String url = tokenBuilder.getPartnerURL(token.getSession_token(), "LOGIN");
		
		assertNotNull(url);
		
		System.out.println(url);
		
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
			System.out.println(CalculateInterest(100000,10,year));
	}

	public long CalculateInterest(long Principal , int Rate , int year)
	{
		return (long)((year > 1 ?  this.CalculateInterest(Principal,Rate,year - 1) : Principal) * ( 1f + calculatedRatePercent(Rate,year)));
	}
   
	public float calculatedRatePercent(int Rate , int Year) {
		return (float)(Rate + (Year % 3 == 0 ? Year % 5 : 0 )) / 100 ;
	}
}
