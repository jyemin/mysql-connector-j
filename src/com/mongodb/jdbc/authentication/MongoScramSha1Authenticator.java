/*
 * Copyright 2017 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mongodb.jdbc.authentication;

import com.mysql.jdbc.SQLError;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Random;

import static com.mongodb.jdbc.authentication.NativeAuthenticationHelper.createAuthenticationHash;

/**
 * An authentication plugin supporting the MongoDB SCRAM-SHA-1 SASL authentication mechanism.
 */
class MongoScramSha1Authenticator extends MongoAuthenticator {
    private static final String GS2_HEADER = "n,,";
    private static final int RANDOM_LENGTH = 24;

    private final Base64Codec base64Codec = new Base64Codec();
    private String clientFirstMessageBare;
    private final RandomStringGenerator randomStringGenerator;
    private String rPrefix;
    private byte[] serverSignature;
    private int step;

    /**
     * Create an instance of the plugin
     */
    public MongoScramSha1Authenticator(final String user, final String password) {
        this(user, password, new DefaultRandomStringGenerator());
    }

    // for easier unit testing
    MongoScramSha1Authenticator(final String user, final String password, final RandomStringGenerator randomStringGenerator) {
        super(user, password);
        this.randomStringGenerator = randomStringGenerator;
    }

    @Override
    byte[] nextAuthenticationStep(final ByteBuffer fromServer) throws SQLException {
        byte[] challengeBytes = new byte[fromServer.getInt()];
        fromServer.get(challengeBytes);
        if (this.step == 0) {
            this.step++;

            return computeClientFirstMessage();
        } else if (this.step == 1) {
            this.step++;

            return computeClientFinalMessage(challengeBytes);
        } else if (this.step == 2) {
            this.step++;
            String serverResponse = encodeUTF8(challengeBytes);
            HashMap<String, String> map = parseServerResponse(serverResponse);

            if (!MessageDigest.isEqual(decodeBase64(map.get("v")), this.serverSignature)) {
                throw SQLError.createSQLException("Server signature was invalid", SQLError.SQL_STATE_GENERAL_ERROR, null);
            }
            return new byte[0];
        } else {
            return new byte[0];
            // TODO: throw
        }
    }

    @Override
    boolean isComplete() {
        return step == 3;
    }

    @Override
    boolean prefixResponseWithSize() {
        return true;
    }

    private byte[] computeClientFirstMessage() throws SQLException {
        String userName = "n=" + prepUserName(getUser());
        this.rPrefix = randomStringGenerator.generate(RANDOM_LENGTH);

        String nonce = "r=" + this.rPrefix;

        this.clientFirstMessageBare = userName + "," + nonce;
        String clientFirstMessage = GS2_HEADER + this.clientFirstMessageBare;

        return decodeUTF8(clientFirstMessage);
    }

    private byte[] computeClientFinalMessage(final byte[] challenge) throws SQLException {
        String serverFirstMessage = encodeUTF8(challenge);

        HashMap<String, String> map = parseServerResponse(serverFirstMessage);
        String r = map.get("r");
        if (!r.startsWith(this.rPrefix)) {
            throw SQLError.createSQLException("Server sent an invalid nonce", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }

        String s = map.get("s");
        String i = map.get("i");

        String channelBinding = "c=" + encodeBase64(decodeUTF8(GS2_HEADER));
        String nonce = "r=" + r;
        String clientFinalMessageWithoutProof = channelBinding + "," + nonce;

        byte[] saltedPassword = hi(createAuthenticationHash(getUser(), getPassword()), decodeBase64(s), Integer.parseInt(i));
        byte[] clientKey = hmac(saltedPassword, "Client Key");
        byte[] storedKey = h(clientKey);
        String authMessage = this.clientFirstMessageBare + "," + serverFirstMessage + "," + clientFinalMessageWithoutProof;
        byte[] clientSignature = hmac(storedKey, authMessage);
        byte[] clientProof = xor(clientKey, clientSignature);
        byte[] serverKey = hmac(saltedPassword, "Server Key");
        this.serverSignature = hmac(serverKey, authMessage);

        String proof = "p=" + encodeBase64(clientProof);
        String clientFinalMessage = clientFinalMessageWithoutProof + "," + proof;

        return decodeUTF8(clientFinalMessage);
    }

    private byte[] decodeBase64(final String str) {
        return this.base64Codec.decode(str);
    }

    private byte[] decodeUTF8(final String str) throws SQLException {
        try {
            return str.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw SQLError.createSQLException("UTF-8 is an unsupported encoding ", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }
    }

    private String encodeBase64(final byte[] bytes) throws SQLException {
        return this.base64Codec.encode(bytes);
    }

    private String encodeUTF8(final byte[] bytes) throws SQLException {
        try {
            return new String(bytes, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw SQLError.createSQLException("UTF-8 is an unsupported encoding ", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }
    }

    private byte[] h(final byte[] data) throws SQLException {
        try {
            return MessageDigest.getInstance("SHA-1").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw SQLError.createSQLException("SHA-1 is an unsupported message digest type", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }
    }

    private byte[] hi(final String password, final byte[] salt, final int iterations) throws SQLException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 20 * 8 /* 20 bytes */);

        SecretKeyFactory keyFactory;
        try {
            keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw SQLError.createSQLException("Unable to find PBKDF2WithHmacSHA1", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }

        try {
            return keyFactory.generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException e) {
            throw SQLError.createSQLException("Invalid key spec for PBKDC2WithHmacSHA1 ", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }
    }

    private byte[] hmac(final byte[] bytes, final String key) throws SQLException {
        SecretKeySpec signingKey = new SecretKeySpec(bytes, "HmacSHA1");

        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw SQLError.createSQLException("Could not find HmacSHA1 ", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }

        try {
            mac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw SQLError.createSQLException("Could not initialize mac", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }

        return mac.doFinal(decodeUTF8(key));
    }

    /**
     * The server provides back key value pairs using an = sign and delimited
     * by a command. All keys are also a single character.
     * For example: a=kg4io3,b=skljsfoiew,c=1203
     */
    private HashMap<String, String> parseServerResponse(final String response) {
        HashMap<String, String> map = new HashMap<String, String>();
        String[] pairs = response.split(",");
        for (String pair : pairs) {
            String[] parts = pair.split("=", 2);
            map.put(parts[0], parts[1]);
        }

        return map;
    }

    private String prepUserName(final String userName) {
        return userName.replace("=", "=3D").replace(",", "=2D");
    }

    private byte[] xor(final byte[] a, final byte[] b) {
        byte[] result = new byte[a.length];

        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }

        return result;
    }

    interface RandomStringGenerator {
        String generate(int length);
    }

    private static class DefaultRandomStringGenerator implements RandomStringGenerator {
        public String generate(final int length) {
            int comma = 44;
            int low = 33;
            int high = 126;
            int range = high - low;

            Random random = new SecureRandom();
            char[] text = new char[length];
            for (int i = 0; i < length; i++) {
                int next = random.nextInt(range) + low;
                while (next == comma) {
                    next = random.nextInt(range) + low;
                }
                text[i] = (char) next;
            }
            return new String(text);
        }
    }
}
