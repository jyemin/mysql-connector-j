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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.sql.SQLException;

import static com.mongodb.jdbc.authentication.BufferHelper.readString;
import static com.mongodb.jdbc.authentication.NativeAuthenticationHelper.createAuthenticationHash;
import static com.mongodb.jdbc.authentication.NativeAuthenticationHelper.hexMD5;

/**
 * A plugin supporting the original MongoDB Challenge-Response authentication mechanism.
 */
class MongoNativeAuthenticator extends MongoAuthenticator {
    MongoNativeAuthenticator(final String user, final String password) {
        super(user, password);
    }

    @Override
    byte[] nextAuthenticationStep(final ByteBuffer fromServer) throws SQLException {
        try {
            String nonce = readString(fromServer);
            String key = hexMD5((nonce + getUser() + createAuthenticationHash(getUser(), getPassword())).getBytes("UTF-8"));
            byte[] keyBytes = key.getBytes("UTF-8");
            ByteArrayOutputStream baos = new ByteArrayOutputStream(keyBytes.length + 1);
            baos.write(keyBytes);
            baos.write(0);
            return baos.toByteArray();

        } catch (UnsupportedEncodingException e) {
            throw SQLError.createSQLException("UTF-8 is unsupported", SQLError.SQL_STATE_GENERAL_ERROR, null);
        } catch (IOException e) {
            throw SQLError.createSQLException("Unexpected IOException", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }
    }

    @Override
    boolean isComplete() {
        return true;
    }

    @Override
    boolean prefixResponseWithSize() {
        return false;
    }
}

