/*
 * Copyright (C) 2026 Apktool contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package brut.androlib.res.decoder;

import brut.androlib.Config;
import brut.androlib.exceptions.AndrolibException;
import brut.androlib.meta.ApkInfo;
import brut.androlib.res.table.ResTable;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.junit.Assert.*;

public class ResourceInputDiagnosticTest {
    private BinaryResourceParser parser() {
        return new BinaryResourceParser(new ResTable(new ApkInfo(), new Config("test")), false, false);
    }

    private String failure(byte[] bytes) throws Exception {
        try {
            parser().parse(new ByteArrayInputStream(bytes), "sample.apk!resources.arsc");
            fail("Malformed resource table must fail");
            return null;
        } catch (AndrolibException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("sample.apk!resources.arsc"));
            assertTrue(ex.getMessage(), ex.getMessage().contains("position=0x"));
            return ex.getMessage();
        }
    }

    @Test
    public void trulyEmptyInputIsIdentified() throws Exception {
        String message = failure(new byte[0]);
        assertTrue(message, message.contains("Input file is empty."));
        assertTrue(message, message.contains("<empty>"));
    }

    @Test
    public void nullChunkIsNonemptyAndReportsHeaderAndPosition() throws Exception {
        byte[] bytes = ByteBuffer.allocate(3268).order(ByteOrder.LITTLE_ENDIAN)
            .putShort((short) 0).putShort((short) 12).putInt(3268).putInt(1).array();
        String message = failure(bytes);
        assertFalse(message, message.contains("Input file is empty."));
        assertTrue(message, message.contains("Non-empty input"));
        assertTrue(message, message.contains("00000c00c40c0000"));
        assertTrue(message, message.contains("position=0x00000cc4"));
    }

    @Test
    public void truncatedHeaderIsNotCalledEmpty() throws Exception {
        String message = failure(new byte[] { 2, 0, 12 });
        assertFalse(message, message.contains("Input file is empty."));
        assertTrue(message, message.contains("02000c"));
    }

    @Test
    public void nullPaddingBeforeValidTableRemainsSupported() throws Exception {
        byte[] bytes = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putShort((short) 0).putShort((short) 8).putInt(8)
            .putShort((short) 2).putShort((short) 12).putInt(12).putInt(0).array();
        parser().parse(new ByteArrayInputStream(bytes));
    }
}
