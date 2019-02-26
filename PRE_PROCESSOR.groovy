import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.InvalidKeyException
import java.security.MessageDigest
import groovy.json.JsonSlurper
import java.text.SimpleDateFormat


//Defined in User Defined Variables
def access_key = vars.get("aws_access_key")
def secret_key = vars.get("aws_secret_key")
def service = vars.get("aws_service_name")
def host = vars.get("aws_host")
def region = vars.get("aws_region")

//Obtain data form the Http Request Sampler
def method = sampler.getMethod()
def url = sampler.getUrl()
def req_path = url.getPath()
def req_query_string = orderQuery(url)
def request_parameters = '';

sampler.getArguments().each {arg ->
    request_parameters = arg.getStringValue().substring(1)
}

//Create the variable x-amz-date 
TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
def now = new Date()
def amzFormat = new SimpleDateFormat( "yyyyMMdd'T'HHmmss'Z'" )
def stampFormat = new SimpleDateFormat( "yyyyMMdd" )
def amzDate = amzFormat.format(now)
def dateStamp = stampFormat.format(now)
vars.put("x_amz_date", amzDate)


//Create a Canonical Request
def canonical_uri = req_path
def canonical_querystring = req_query_string
def canonical_headers = "host:" + host + "\n" + "x-amz-date:" + amzDate + "\n"
def signed_headers = "host;x-amz-date"
def payload_hash = getHexDigest(request_parameters)
def canonical_request = method + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_hash


//Create the String to Sign
def algorithm = "AWS4-HMAC-SHA256"
def credential_scope = dateStamp + "/" + region + "/" + service + "/" + "aws4_request"
def hash_canonical_request = getHexDigest(canonical_request)
def string_to_sign = algorithm + "\n" +  amzDate + "\n" +  credential_scope + "\n" +  hash_canonical_request

//Calculate the String to Sign
def signing_key = getSignatureKey(secret_key, dateStamp, region, service)
def signature = hmac_sha256Hex(signing_key, string_to_sign)

//Add Signing information to Variable
def authorization_header = algorithm + " " + "Credential=" + access_key + "/" + credential_scope + ", " +  "SignedHeaders=" + signed_headers + ", " + "Signature=" + signature
vars.put("aws_authorization", authorization_header)


def hmac_sha256(secretKey, data) {
    Mac mac = Mac.getInstance("HmacSHA256")
    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256")
    mac.init(secretKeySpec)
    byte[] digest = mac.doFinal(data.getBytes())
    return digest
}

def hmac_sha256Hex(secretKey, data) {
    def result = hmac_sha256(secretKey, data)
    return result.encodeHex()
}

def getSignatureKey(key, dateStamp, regionName, serviceName) {
    def kDate = hmac_sha256(("AWS4" + key).getBytes(), dateStamp)
    def kRegion = hmac_sha256(kDate, regionName)
    def kService = hmac_sha256(kRegion, serviceName)
    def kSigning = hmac_sha256(kService, "aws4_request")
    return kSigning
}

def getHexDigest(text) {
    log.info("text:"+text)
    def md = MessageDigest.getInstance("SHA-256")
    md.update(text.getBytes())
    return md.digest().encodeHex()
}

public static String orderQuery(URL url) throws UnsupportedEncodingException {

    def orderQueryString = "";
    Map<String, String> queryPairs = new LinkedHashMap<>();
    String queryParams = url.getQuery();

    if (queryParams != null) {
        String[] pairs = queryParams.split("&");
    
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            queryPairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        def orderQueryArray = new TreeMap<String, String>(queryPairs);
        orderQueryString  = urlEncodeUTF8(orderQueryArray)
    }
    return orderQueryString;
}

public static String urlEncodeUTF8(String s) {
    try {
        return URLEncoder.encode(s, "UTF-8");
    } catch (UnsupportedEncodingException e) {
        throw new UnsupportedOperationException(e);
    }
}

public static String urlEncodeUTF8(Map<?,?> map) {
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<?,?> entry : map.entrySet()) {
        if (sb.length() > 0) {
            sb.append("&");
        }
        sb.append(String.format("%s=%s",
            urlEncodeUTF8(entry.getKey().toString()),
            urlEncodeUTF8(entry.getValue().toString())
        ));
    }
    return sb.toString();       
}