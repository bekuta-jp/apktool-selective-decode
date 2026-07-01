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

import brut.androlib.exceptions.AndrolibException;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UnreadableApkEntryTest extends BaseTest {
    private static final String TEST_APK = "issue1680.apk";
    private static final String BAD_LIB = "lib/armeabi-v7a/libbad.so";
    private static final String GOOD_LIB = "lib/armeabi-v7a/libgood.so";

    @BeforeClass
    public static void beforeClass() throws Exception {
        copyResourceDir(UnreadableApkEntryTest.class, "issue1680", sTmpDir);
    }

    @Test
    public void unreadableNonDexEntryIsSkipped() throws Exception {
        File testApk = createApkWithUnreadableEntry("unreadable-lib.apk", BAD_LIB);
        File testDir = new File(testApk + ".out");

        sConfig.setDecodeDexMode(Config.DecodeMode.DECODE);
        sConfig.setDecodeManifestMode(Config.DecodeMode.SKIP);
        sConfig.setDecodeResMode(Config.DecodeMode.SKIP);
        new ApkDecoder(testApk, sConfig).decode(testDir);

        assertTrue(new File(testDir, "smali").isDirectory());
        assertTrue(new File(testDir, GOOD_LIB).isFile());
        assertFalse(new File(testDir, BAD_LIB).exists());
    }

    @Test
    public void unreadableDexEntryIsNotOpenedWhenDexIsSkipped() throws Exception {
        File testApk = createApkWithUnreadableEntry("unreadable-skipped-dex.apk", "classes.dex");
        File testDir = new File(testApk + ".out");

        sConfig.setDecodeDexMode(Config.DecodeMode.SKIP);
        sConfig.setDecodeManifestMode(Config.DecodeMode.SKIP);
        sConfig.setDecodeResMode(Config.DecodeMode.SKIP);
        new ApkDecoder(testApk, sConfig).decode(testDir);

        assertFalse(new File(testDir, "smali").exists());
        assertFalse(new File(testDir, "classes.dex").exists());
    }

    @Test(expected = AndrolibException.class)
    public void unreadableSelectedDexEntryIsRejected() throws Exception {
        File testApk = createApkWithUnreadableEntry("unreadable-selected-dex.apk", "classes.dex");
        File testDir = new File(testApk + ".out");

        sConfig.setDecodeDexMode(Config.DecodeMode.DECODE);
        sConfig.setDecodeManifestMode(Config.DecodeMode.SKIP);
        sConfig.setDecodeResMode(Config.DecodeMode.SKIP);
        new ApkDecoder(testApk, sConfig).decode(testDir);
    }

    private static File createApkWithUnreadableEntry(String outputName, String unreadableEntry)
            throws Exception {
        File sourceApk = new File(sTmpDir, TEST_APK);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int unreadableOffset = -1;

        try (
            InputStream fileIn = Files.newInputStream(sourceApk.toPath());
            ZipInputStream in = new ZipInputStream(fileIn);
            ZipOutputStream out = new ZipOutputStream(buffer)
        ) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                int entryOffset = buffer.size();
                out.putNextEntry(new ZipEntry(entry.getName()));
                copy(in, out);
                out.closeEntry();
                if (entry.getName().equals(unreadableEntry)) {
                    unreadableOffset = entryOffset;
                }
            }

            if (unreadableEntry.equals(BAD_LIB)) {
                writeEntry(out, GOOD_LIB, new byte[] { 1, 2, 3 });
                unreadableOffset = buffer.size();
                writeEntry(out, BAD_LIB, new byte[] { 4, 5, 6 });
            }
        }

        if (unreadableOffset < 0) {
            throw new IllegalArgumentException("Entry not found: " + unreadableEntry);
        }

        byte[] apkData = buffer.toByteArray();
        apkData[unreadableOffset] = 0;
        apkData[unreadableOffset + 1] = 0;
        apkData[unreadableOffset + 2] = 0;
        apkData[unreadableOffset + 3] = 0;

        File outputApk = new File(sTmpDir, outputName);
        Files.write(outputApk.toPath(), apkData);
        return outputApk;
    }

    private static void writeEntry(ZipOutputStream out, String name, byte[] data) throws Exception {
        out.putNextEntry(new ZipEntry(name));
        out.write(data);
        out.closeEntry();
    }

    private static void copy(InputStream in, ZipOutputStream out) throws Exception {
        byte[] data = new byte[8192];
        int count;
        while ((count = in.read(data)) != -1) {
            out.write(data, 0, count);
        }
    }
}
