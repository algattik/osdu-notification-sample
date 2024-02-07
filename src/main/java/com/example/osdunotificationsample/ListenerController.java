package com.example.osdunotificationsample;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;

@Controller
public class ListenerController {

    @GetMapping("/")
    public Object challenge(@RequestParam("crc") String crc,
                              @RequestParam("hmac") String hmac) throws Exception {
        String secret = "$ekrit";
        verifyHmacSignature(hmac, secret);

        String response = getResponseHash( secret + crc);
        return Collections.singletonMap("responseHash", response);
    }

    private String getResponseHash(String input) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        var response = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(response);
    }

    private static final String HMAC_SHA_256 = "HmacSHA256";
    private static final String DATA_FORMAT = "{\"expireMillisecond\": \"%s\",\"hashMechanism\": \"hmacSHA256\",\"endpointUrl\": \"%s\",\"nonce\": \"%s\"}";
    private static final String NOTIFICATION_SERVICE = "de-notification-service";
    private static final long EXPIRE_DURATION = 30000L;


    private static final String MISSING_HMAC_SIGNATURE = "Missing HMAC signature";
    private static final String MISSING_SECRET_VALUE = "Missing secret value";
    private static final String INVALID_SIGNATURE = "Invalid signature";
    private static final String MISSING_ATTRIBUTES_IN_SIGNATURE = "Missing attributes in signature";
    private static final String ERROR_GENERATING_SIGNATURE = "Error generating signature";
    private static final String SIGNATURE_EXPIRED = "Signature expired";

    private void verifyHmacSignature(String hmac, String secret) throws Exception {
        if (Strings.isNullOrEmpty(hmac)) {
            throw new Exception(MISSING_HMAC_SIGNATURE);
        }
        if (Strings.isNullOrEmpty(secret)) {
            throw new Exception(MISSING_SECRET_VALUE);
        }
        String[] tokens = hmac.split("\\.");
        if (tokens.length != 2) {
            throw new Exception(INVALID_SIGNATURE);
        }
        byte[] dataBytes = Base64.getDecoder().decode(tokens[0]);
        String requestSignature = tokens[1];

        String data = new String(dataBytes, StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper();

        HmacData hmacData = mapper.readValue(data, HmacData.class);
        String url = hmacData.getEndpointUrl();
        String nonce = hmacData.getNonce();
        String expireTime = hmacData.getExpireMillisecond();
        if (Strings.isNullOrEmpty(url) || Strings.isNullOrEmpty(nonce) || Strings.isNullOrEmpty(expireTime)) {
            throw new Exception(MISSING_ATTRIBUTES_IN_SIGNATURE);
        }
        String newSignature = getSignedSignature(url, secret, expireTime, nonce);
        if (!requestSignature.equalsIgnoreCase(newSignature)) {
            throw new Exception(INVALID_SIGNATURE);
        }
    }

    private String getSignedSignature(String url, String secret, String expireTime, String nonce) throws Exception {
        if (Strings.isNullOrEmpty(url) || Strings.isNullOrEmpty(secret)) {
            throw new Exception(ERROR_GENERATING_SIGNATURE);
        }
        final long expiry = Long.parseLong(expireTime);
        if (System.currentTimeMillis() > expiry) {
            throw new Exception(SIGNATURE_EXPIRED);
        }
        String timeStamp = String.valueOf(expiry - EXPIRE_DURATION);
        String data = String.format(DATA_FORMAT, expireTime, url, nonce);
        try {
            final byte[] signature = getSignature(secret, nonce, timeStamp, data);
            return DatatypeConverter.printHexBinary(signature).toLowerCase();
        } catch (Exception ex) {
            throw new Exception(ERROR_GENERATING_SIGNATURE, ex);
        }
    }

    private byte[] getSignature(String secret, String nonce, String timeStamp, String data) throws Exception {
        final byte[] secretBytes = DatatypeConverter.parseHexBinary(secret);
        final byte[] nonceBytes = DatatypeConverter.parseHexBinary(nonce);
        final byte[] encryptedNonce = computeHmacSha256(nonceBytes, secretBytes);
        final byte[] encryptedTimestamp = computeHmacSha256(timeStamp, encryptedNonce);
        final byte[] signedKey = computeHmacSha256(NOTIFICATION_SERVICE, encryptedTimestamp);
        return computeHmacSha256(data, signedKey);
    }

    private byte[] computeHmacSha256(final String data, final byte[] key) throws Exception {
        final Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(new SecretKeySpec(key, HMAC_SHA_256));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] computeHmacSha256(final byte[] data, final byte[] key) throws Exception {
        final Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(new SecretKeySpec(key, HMAC_SHA_256));
        return mac.doFinal(data);
    }
    
    private static class HmacData {

        private String endpointUrl;
        private String nonce;
        private String expireMillisecond;

        public String getEndpointUrl() {
            return endpointUrl;
        }

        public void setEndpointUrl(String endpointUrl) {
            this.endpointUrl = endpointUrl;
        }

        public String getNonce() {
            return nonce;
        }

        public void setNonce(String nonce) {
            this.nonce = nonce;
        }

        public String getExpireMillisecond() {
            return expireMillisecond;
        }

        public void setExpireMillisecond(String expireMillisecond) {
            this.expireMillisecond = expireMillisecond;
        }
    }

}
