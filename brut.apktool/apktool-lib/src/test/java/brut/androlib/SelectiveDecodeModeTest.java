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
package brut.androlib;

import java.io.File;
import java.util.Arrays;

import org.junit.*;
import static org.junit.Assert.*;

public class SelectiveDecodeModeTest extends BaseTest {
    private static final String TEST_APK = "issue1680.apk";

    private static final byte[] XML_HEADER = {
        0x3C, // <
        0x3F, // ?
        0x78, // x
        0x6D, // m
        0x6C, // l
        0x20, // (empty)
    };

    @BeforeClass
    public static void beforeClass() throws Exception {
        copyResourceDir(SelectiveDecodeModeTest.class, "issue1680", sTmpDir);
    }

    @Test
    public void decodeDexSkipTest() throws Exception {
        sConfig.setDecodeDexMode(Config.DecodeMode.SKIP);
        sConfig.setDecodeManifestMode(Config.DecodeMode.SKIP);
        sConfig.setDecodeResMode(Config.DecodeMode.SKIP);

        File testApk = new File(sTmpDir, TEST_APK);
        File testDir = new File(testApk + ".out.selective.dex.skip");
        new ApkDecoder(testApk, sConfig).decode(testDir);

        assertFalse(new File(testDir, "classes.dex").isFile());
        assertFalse(new File(testDir, "smali").isDirectory());
    }

    @Test
    public void decodeManifestRawTest() throws Exception {
        sConfig.setDecodeDexMode(Config.DecodeMode.SKIP);
        sConfig.setDecodeManifestMode(Config.DecodeMode.RAW);
        sConfig.setDecodeResMode(Config.DecodeMode.SKIP);

        File testApk = new File(sTmpDir, TEST_APK);
        File testDir = new File(testApk + ".out.selective.manifest.raw");
        new ApkDecoder(testApk, sConfig).decode(testDir);

        assertTrue(new File(testDir, "AndroidManifest.xml").isFile());
        assertFalse(Arrays.equals(XML_HEADER, readHeaderOfFile(new File(testDir, "AndroidManifest.xml"), 6)));
    }

    @Test
    public void decodeManifestWithResourcesButSkipResourceOutputTest() throws Exception {
        File testApk = new File(sTmpDir, TEST_APK);

        sConfig.setDecodeDexMode(Config.DecodeMode.SKIP);
        sConfig.setDecodeManifestMode(Config.DecodeMode.DECODE);
        sConfig.setDecodeResMode(Config.DecodeMode.DECODE);

        File controlDir = new File(testApk + ".out.selective.manifest.control");
        new ApkDecoder(testApk, sConfig).decode(controlDir);

        sConfig.setDecodeDexMode(Config.DecodeMode.SKIP);
        sConfig.setDecodeManifestMode(Config.DecodeMode.DECODE);
        sConfig.setDecodeResMode(Config.DecodeMode.SKIP);

        File testDir = new File(testApk + ".out.selective.manifest.res.skip.loaded");
        new ApkDecoder(testApk, sConfig).decode(testDir);

        assertTrue(new File(testDir, "AndroidManifest.xml").isFile());
        assertFalse(new File(testDir, "resources.arsc").isFile());
        assertFalse(new File(testDir, "res").isDirectory());
        assertFalse(new File(testDir, "unknown/res").isDirectory());
        compareXmlFiles(controlDir, testDir, "AndroidManifest.xml");
    }

    @Test
    public void decodeManifestAndResSkipTest() throws Exception {
        sConfig.setDecodeDexMode(Config.DecodeMode.SKIP);
        sConfig.setDecodeManifestMode(Config.DecodeMode.SKIP);
        sConfig.setDecodeResMode(Config.DecodeMode.SKIP);

        File testApk = new File(sTmpDir, TEST_APK);
        File testDir = new File(testApk + ".out.selective.manifest.res.skip");
        new ApkDecoder(testApk, sConfig).decode(testDir);

        assertFalse(new File(testDir, "AndroidManifest.xml").isFile());
        assertFalse(new File(testDir, "original/AndroidManifest.xml").isFile());
        assertFalse(new File(testDir, "resources.arsc").isFile());
        assertFalse(new File(testDir, "res").isDirectory());
        assertFalse(new File(testDir, "unknown/res").isDirectory());
    }
}
