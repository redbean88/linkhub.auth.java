package kr.co.linkhub.auth.test;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import kr.co.linkhub.auth.LinkhubException;
import kr.co.linkhub.auth.Token;
import kr.co.linkhub.auth.TokenBuilder;

import org.junit.Test;

public class TokenBuilder_Test {
	
	private final String LinkID = "TESTER";
	private final String SecretKey = "RTY69sOhR4AtjogjHIhnArYoyRlrFlIXc2inDJk6x2M=";
	
	@Test
	public void Build_Success_Test() throws LinkhubException {
		
		TokenBuilder tokenBuilder = TokenBuilder.getInstance(LinkID, SecretKey)
									.ServiceID("POPBILL_TEST")
									.addScope("member")
									.addScope("110");
	
		Token token = tokenBuilder.build("1231212312");
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());
		
		token = tokenBuilder.build("4108600477");
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		assertEquals("TESTER", token.getLinkID());
	}
	
	@Test(expected=LinkhubException.class)
	public void Build_Fail_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.getInstance(LinkID, SecretKey);
		
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
		TokenBuilder tokenBuilder = TokenBuilder.getInstance(LinkID, SecretKey);
		
		Token token = tokenBuilder
						.ServiceID("POPBILL_TEST")
						.addScope("member")
						.addScope("110")
						.build("1231212312");
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		double remainPoint = tokenBuilder.getBalance(token.getSession_token());
		
		assertTrue(remainPoint >= 0);
		
		System.out.println("잔여포인트 : " + String.valueOf(remainPoint));
		
	}
	
	@Test
	public void GetPartnerBalance_Success_Test() throws LinkhubException {
		TokenBuilder tokenBuilder = TokenBuilder.getInstance(LinkID, SecretKey);
		
		List<String> scopes = new ArrayList<String>();
		scopes.add("member");
		
		Token token = tokenBuilder
							.ServiceID("POPBILL_TEST")
							.addScope("member")
							.addScope("110")
							.build("1231212312");
		
		assertNotNull(token);
		
		assertNotNull(token.getSession_token());
		
		double remainPoint = tokenBuilder.getPartnerBalance(token.getSession_token());
		
		assertTrue(remainPoint >= 0);
		
		System.out.println("파트너 잔여포인트 : " + String.valueOf(remainPoint));
		
	}

}
