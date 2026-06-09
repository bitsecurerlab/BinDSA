package org.json.simple;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class JSONObject extends HashMap<String, Object> {
	private static final long serialVersionUID = 1L;

	public String toJSONString() {
		StringBuilder sb = new StringBuilder();
		sb.append("{");
		Iterator<Map.Entry<String, Object>> it = entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<String, Object> entry = it.next();
			sb.append(JSONValue.toJSONString(entry.getKey()));
			sb.append(":");
			sb.append(JSONValue.toJSONString(entry.getValue()));
			if (it.hasNext())
				sb.append(",");
		}
		sb.append("}");
		return sb.toString();
	}

	@Override
	public String toString() {
		return toJSONString();
	}
}
