import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import ghidra.program.model.listing.Function;

public class JsonUtils {
    public static JSONObject getResolvedCallTargetEntry(CallSiteNode csite, List<Function> targetList) {
        JSONObject entry = new JSONObject();
						entry.put("call_site", String.format("0x%x", csite.getLoc().getOffset()));
						entry.put("caller", csite.getFuncName());
						entry.put("tokens", csite.getTokens());
						entry.put("count", targetList.size());

                        JSONArray targetsArr = new JSONArray();
                        for (Function func : targetList) {
                            String fp = String.format("0x%x", func.getEntryPoint().getOffset());
                            // String name = func.getName();
                            targetsArr.add(fp);
                        }
						entry.put("targets", targetsArr);
                        return entry;
    }
}
