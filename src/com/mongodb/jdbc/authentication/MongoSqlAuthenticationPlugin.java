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
 *
 */

package com.mongodb.jdbc.authentication;

import com.mysql.jdbc.AuthenticationPlugin;
import com.mysql.jdbc.Buffer;
import com.mysql.jdbc.Connection;
import com.mysql.jdbc.SQLError;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class MongoSqlAuthenticationPlugin implements AuthenticationPlugin {
    private String user;
    private String password;
    private List<MongoAuthenticator> authenticators;

    public String getProtocolPluginName() {
        return "mongosql_auth";
    }

    public boolean requiresConfidentiality() {
        return false;
    }

    public boolean isReusable() {
        return false;
    }

    public void setAuthenticationParameters(final String user, final String password) {
        this.user = user.contains("?") ? user.substring(0, user.lastIndexOf("?")) : user;
        this.password = password;
    }

    public boolean nextAuthenticationStep(final Buffer fromServer, final List<Buffer> toServer) throws SQLException {
        toServer.clear();

        if (fromServer == null) {
            toServer.add(new Buffer(new byte[0]));
            return true;
        }

        ByteBuffer byteBuffer = ByteBuffer.wrap(fromServer.getByteBuffer(), 0, fromServer.getBufLength());
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        if (authenticators == null) {
            String mechanism = BufferHelper.readString(byteBuffer);
            int iterations = byteBuffer.getInt();
            authenticators = new ArrayList<MongoAuthenticator>(iterations);
            for (int i = 0; i < iterations; i++) {
                authenticators.add(createAuthenticator(mechanism));
            }
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        boolean isComplete = true;
        for (MongoAuthenticator authenticator : authenticators) {
            byte[] bytes = authenticator.nextAuthenticationStep(byteBuffer);
            if (authenticator.prefixResponseWithSize()) {
                ByteBuffer sizeBuffer = ByteBuffer.allocate(4);
                sizeBuffer.order(ByteOrder.LITTLE_ENDIAN);
                sizeBuffer.putInt(bytes.length);
                writeToOutputStream(baos, sizeBuffer.array());
            }
            writeToOutputStream(baos, bytes);
            if (!authenticator.isComplete()) {
                isComplete = false;
            }
        }

        toServer.add(new Buffer(baos.toByteArray()));

        return isComplete;
    }

    private void writeToOutputStream(final ByteArrayOutputStream baos, final byte[] array) throws SQLException {
        try {
            baos.write(array);
        } catch (IOException e) {
            throw SQLError.createSQLException("Unexpected IOException ", SQLError.SQL_STATE_GENERAL_ERROR, null);
        }
    }

    private MongoAuthenticator createAuthenticator(final String mechanism) throws SQLException {
        if (mechanism.equals("MONGODB-CR")) {
            return new MongoNativeAuthenticator(user, password);
        } else if (mechanism.equals("SCRAM-SHA-1")) {
            return new MongoScramSha1Authenticator(user, password);
        } else if (mechanism.equals("PLAIN")) {
            return new PlainAuthenticator(user, password);
        } else {
            throw SQLError.createSQLException("Unsupported authentication mechanism " + mechanism, SQLError.SQL_STATE_GENERAL_ERROR, null);
        }
    }

    public void init(final Connection conn, final Properties props) throws SQLException {
    }

    public void destroy() {
    }
}
