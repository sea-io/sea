import com.sea.util;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.MDC;

public class LogUtil {

    public static final String PRODUCT_NAME = "product_id";

    public static final String MODULE_NAME = "module_id";

    public static final String NODE_NAME = "node_id";

    public static final String PROCESS_NAME = "process_id";

    private static Map<String, String> unvariableInfoMap = new HashMap<String, String>();

    public static void registerLocationInfo(String productId, String moduleId, String nodeId) {
        check(PRODUCT_NAME, productId);
        check(MODULE_NAME, moduleId);
        check(NODE_NAME, nodeId);

        unvariableInfoMap.put(PRODUCT_NAME, productId);
        unvariableInfoMap.put(MODULE_NAME, moduleId);
        unvariableInfoMap.put(NODE_NAME, nodeId);
    }

    private static void check(String infoName, String infoValue) {
        if(infoValue == null || "".equals(infoValue)) {
            throw new RuntimeException(infoName + " must be set");
        }
    }

    public static void registerProcessID(String processID) {
        MDC.clear();
        check(PROCESS_NAME, processID);

        MDC.put("product", unvariableInfoMap.get(PRODUCT_NAME));
        MDC.put("module", unvariableInfoMap.get(MODULE_NAME));
        MDC.put("node", unvariableInfoMap.get(NODE_NAME));
        MDC.put("process", processID);
    }

    public static void registerInteractionUUID(String interactionUUID) {
        MDC.put("uuid", interactionUUID);
    }

    public static String getProcessID() {
        return MDC.get("process");
    }

    public static String getIntetractionUUID() {
        return MDC.get("uuid");
    }

    public static String getProductID() {
        return unvariableInfoMap.get(PRODUCT_NAME);
    }

    public static String getModuleID() {
        return unvariableInfoMap.get(MODULE_NAME);
    }

    public static String getNodeID() {
        return unvariableInfoMap.get(NODE_NAME);
    }
}
