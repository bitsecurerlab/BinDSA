package org.json.simple;

import java.util.Map;

class JSONValue {
	static String toJSONString(Object value) {
		if (value == null)
			return "null";
		if (value instanceof String)
			return quote((String) value);
		if (value instanceof Number || value instanceof Boolean)
			return value.toString();
		if (value instanceof JSONObject)
			return ((JSONObject) value).toJSONString();
		if (value instanceof JSONArray)
			return ((JSONArray) value).toJSONString();
		if (value instanceof Map<?, ?>) {
			JSONObject obj = new JSONObject();
			for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
				obj.put(String.valueOf(entry.getKey()), entry.getValue());
			}
			return obj.toJSONString();
		}
		return quote(value.toString());
	}

	private static String quote(String s) {
		StringBuilder sb = new StringBuilder();
		sb.append("\"");
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
			case '"':
				sb.append("\\\"");
				break;
			case '\\':
				sb.append("\\\\");
				break;
			case '\b':
				sb.append("\\b");
				break;
			case '\f':
				sb.append("\\f");
				break;
			case '\n':
				sb.append("\\n");
				break;
			case '\r':
				sb.append("\\r");
				break;
			case '\t':
				sb.append("\\t");
				break;
			default:
				if (c < 0x20) {
					String hex = Integer.toHexString(c);
					sb.append("\\u");
					for (int j = hex.length(); j < 4; j++)
						sb.append("0");
					sb.append(hex);
				} else {
					sb.append(c);
				}
			}
		}
		sb.append("\"");
		return sb.toString();
	}
}
