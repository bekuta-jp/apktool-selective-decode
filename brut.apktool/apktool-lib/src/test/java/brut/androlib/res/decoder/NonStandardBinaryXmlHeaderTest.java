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

import brut.androlib.res.data.ResChunkHeader;

import org.junit.Test;
import org.xmlpull.v1.XmlPullParserException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class NonStandardBinaryXmlHeaderTest {
    private static final byte RES_XML_ALTERNATE_TYPE = 0x09;

    @Test
    public void nonStandardHeaderWithStringPoolIsAccepted() throws Exception {
        byte[] manifest = MalformedBinaryXmlAttributeTest.readManifestFixture();
        int originalAttributeCount =
            MalformedBinaryXmlAttributeTest.readFirstStartTagAttributeCount(manifest);

        manifest[0] = RES_XML_ALTERNATE_TYPE;

        int decodedAttributeCount =
            MalformedBinaryXmlAttributeTest.readFirstStartTagAttributeCount(manifest);
        assertTrue(originalAttributeCount > 0);
        assertEquals(originalAttributeCount, decodedAttributeCount);
    }

    @Test(expected = XmlPullParserException.class)
    public void nonStandardHeaderWithoutStringPoolIsRejected() throws Exception {
        byte[] manifest = MalformedBinaryXmlAttributeTest.readManifestFixture();
        manifest[0] = RES_XML_ALTERNATE_TYPE;
        manifest[ResChunkHeader.SIZE] = (byte) ResChunkHeader.RES_TABLE_TYPE;

        MalformedBinaryXmlAttributeTest.readFirstStartTagAttributeCount(manifest);
    }
}
