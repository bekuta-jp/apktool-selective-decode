/*
 *  Copyright (C) 2010 Ryszard Wiśniewski <brut.alll@gmail.com>
 *  Copyright (C) 2010 Connor Tumbleson <connor.tumbleson@gmail.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package brut.androlib.res.decoder;

import brut.androlib.Config;
import brut.androlib.meta.ApkInfo;
import brut.androlib.res.data.ResChunkHeader;
import brut.androlib.res.table.ResTable;

import org.junit.Test;
import org.xmlpull.v1.XmlPullParser;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class MalformedBinaryXmlAttributeTest {
    @Test
    public void malformedAttributeIsSkipped() throws Exception {
        byte[] manifest = readManifestFixture();
        int originalAttributeCount = readFirstStartTagAttributeCount(manifest);

        corruptFirstAttributeValueSize(manifest);

        int decodedAttributeCount = readFirstStartTagAttributeCount(manifest);
        assertTrue(originalAttributeCount > 0);
        assertEquals(originalAttributeCount - 1, decodedAttributeCount);
    }

    static int readFirstStartTagAttributeCount(byte[] manifest) throws Exception {
        Config config = new Config("test");
        ResTable table = new ResTable(new ApkInfo(), config);
        BinaryXmlResourceParser parser = new BinaryXmlResourceParser(table, false, true);
        parser.setInput(new ByteArrayInputStream(manifest), null);

        int event;
        do {
            event = parser.nextToken();
        } while (event != XmlPullParser.START_TAG && event != XmlPullParser.END_DOCUMENT);

        assertEquals(XmlPullParser.START_TAG, event);
        return parser.getAttributeCount();
    }

    private static void corruptFirstAttributeValueSize(byte[] manifest) {
        ByteBuffer buffer = ByteBuffer.wrap(manifest).order(ByteOrder.LITTLE_ENDIAN);
        int xmlSize = buffer.getInt(4);
        int position = 8;

        while (position + 8 <= xmlSize) {
            int type = Short.toUnsignedInt(buffer.getShort(position));
            int chunkSize = buffer.getInt(position + 4);
            if (type == ResChunkHeader.RES_XML_START_ELEMENT_TYPE) {
                int attributeExtension = position + 16;
                int attributeStart = Short.toUnsignedInt(buffer.getShort(attributeExtension + 8));
                int attributeCount = Short.toUnsignedInt(buffer.getShort(attributeExtension + 12));
                assertTrue(attributeCount > 0);

                int firstAttribute = attributeExtension + attributeStart;
                buffer.putShort(firstAttribute + 12, (short) 0);
                return;
            }
            assertTrue(chunkSize >= 8);
            position += chunkSize;
        }

        throw new AssertionError("No start element with attributes found.");
    }

    static byte[] readManifestFixture() throws IOException {
        InputStream resource = MalformedBinaryXmlAttributeTest.class
            .getResourceAsStream("/issue1680/issue1680.apk");
        assertNotNull(resource);

        try (InputStream apk = resource; ZipInputStream zip = new ZipInputStream(apk)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (entry.getName().equals("AndroidManifest.xml")) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = zip.read(buffer)) != -1) {
                        out.write(buffer, 0, read);
                    }
                    return out.toByteArray();
                }
            }
        }

        throw new AssertionError("AndroidManifest.xml not found in fixture.");
    }
}
