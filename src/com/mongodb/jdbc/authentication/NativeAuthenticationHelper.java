/*
 * Copyright 2008-2017 MongoDB, Inc.
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;

final class NativeAuthenticationHelper {

    static String createAuthenticationHash(final String user, final String password) throws SQLException {
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream(user.length() + 20 + password.length());
            bout.write(user.getBytes("UTF-8"));
            bout.write(":mongo:".getBytes("UTF-8"));
            bout.write(password.getBytes("UTF-8"));

            return hexMD5(bout.toByteArray());
        } catch (IOException e) {
            throw SQLError.createSQLException("Unexpected IOException ", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }
    }

    static String hexMD5(final byte[] data) throws SQLException {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");

            md5.reset();
            md5.update(data);
            byte[] digest = md5.digest();

            return toHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw SQLError.createSQLException("MD5 is an unsupported digest type", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }
    }

    private static String toHex(final byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (final byte b : bytes) {
            String s = Integer.toHexString(0xff & b);

            if (s.length() < 2) {
                sb.append("0");
            }
            sb.append(s);
        }
        return sb.toString();
    }


    private NativeAuthenticationHelper() {
    }
}
