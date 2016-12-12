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

import com.mysql.jdbc.Buffer;

import java.nio.ByteBuffer;
import java.sql.SQLException;

abstract class MongoAuthenticator {
    private String user;
    private String password;

    MongoAuthenticator(final String user, final String password) {
        this.user = user;
        this.password = password;
    }

    String getUser() {
        return user;
    }

    String getPassword() {
        return password;
    }

    abstract byte[] nextAuthenticationStep(ByteBuffer fromServer) throws SQLException;

    abstract boolean isComplete();

    abstract boolean prefixResponseWithSize();
}
