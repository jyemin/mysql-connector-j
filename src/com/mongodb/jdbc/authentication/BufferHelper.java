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

import com.mysql.jdbc.StringUtils;

import java.nio.ByteBuffer;

final class BufferHelper {
    static String readString(final ByteBuffer byteBuffer) {
        int i = byteBuffer.position();
        int len = 0;
        int maxLen = byteBuffer.limit();

        while ((i < maxLen) && (byteBuffer.get(i) != 0)) {
            len++;
            i++;
        }

        String s = StringUtils.toString(byteBuffer.array(), byteBuffer.position(), len);
        byteBuffer.position(byteBuffer.position() + len + 1);

        return s;
    }

    private BufferHelper() {
    }
}
