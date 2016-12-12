/*
 * Copyright (c) 2008 - 2013 10gen, Inc. <http://10gen.com>
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
 *
 */

package com.mongodb.jdbc.authentication;

import com.mysql.jdbc.SQLError;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.sql.SQLException;

class PlainAuthenticator extends MongoAuthenticator {
    PlainAuthenticator(final String user, final String password) {
        super(user, password);
    }

    @Override
    byte[] nextAuthenticationStep(final ByteBuffer fromServer) throws SQLException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(0);
            baos.write(getUser().getBytes("UTF-8"));
            baos.write(0);
            baos.write(getPassword().getBytes("UTF-8"));
            return baos.toByteArray();
        } catch (IOException e) {
            throw SQLError.createSQLException("UTF-8 is unsupported", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }
    }

    @Override
    boolean isComplete() {
        return true;
    }

    @Override
    boolean prefixResponseWithSize() {
        return true;
    }
}
