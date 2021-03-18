package kr.co.linkhub.auth.test.util;

import java.util.LinkedHashMap;
import java.util.Map;

public class PrettyPrint {

	private static PrettyPrint prettyPrint = null;
	
	private PrettyPrint() {
	}
	
	public static PrettyPrint getInstance() {
		if(prettyPrint == null) return new PrettyPrint();
		return prettyPrint;
	}


	final static Map<String, String> printMap = new LinkedHashMap<String, String>();
	
	public static PrettyPrint setTitleNValue(String title, String value) {
		printMap.put(title, value);
		return prettyPrint;
	}
	
	
	public static void print() {
		StringBuilder sb = new StringBuilder();
		sb.append("===============================================\n");
		for (Map.Entry<String, String> elem : printMap.entrySet()) {
			sb.append(elem.getKey()+":");
			sb.append(elem.getValue()+"\n");
		}
		sb.append("===============================================\n");
		System.out.println(sb.toString());
		printMap.clear();// 초기화
	}
}
