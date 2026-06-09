package org.json.simple;

import java.util.ArrayList;
import java.util.Iterator;

public class JSONArray extends ArrayList<Object> {
	private static final long serialVersionUID = 1L;

	public String toJSONString() {
		StringBuilder sb = new StringBuilder();
		sb.append("[");
		Iterator<Object> it = iterator();
		while (it.hasNext()) {
			sb.append(JSONValue.toJSONString(it.next()));
			if (it.hasNext())
				sb.append(",");
		}
		sb.append("]");
		return sb.toString();
	}

	@Override
	public String toString() {
		return toJSONString();
	}
}
