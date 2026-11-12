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
package brut.androlib;

import brut.util.ZipUtils;
import brut.directory.ZipRODirectory;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;

public class ZipMetadataCharsetTest {
    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private File archive(Charset charset, String name, String comment) throws Exception {
        File apk = tmp.newFile();
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(apk.toPath()), charset)) {
            ZipEntry entry = new ZipEntry(name);
            entry.setComment(comment);
            out.putNextEntry(entry);
            out.write(new byte[] { 1, 2, 3 });
            out.closeEntry();
        }
        return apk;
    }

    private void setUtf8Flag(File apk, boolean set) throws Exception {
        setUtf8Flag(apk, set, null);
    }

    private void setUtf8Flag(File apk, boolean set, String targetName) throws Exception {
        byte[] bytes = Files.readAllBytes(apk.toPath());
        for (int i = 0; i + 10 < bytes.length; i++) {
            if (bytes[i] == 'P' && bytes[i + 1] == 'K') {
                int offset = bytes[i + 2] == 3 && bytes[i + 3] == 4 ? 7
                    : bytes[i + 2] == 1 && bytes[i + 3] == 2 ? 9 : -1;
                if (offset != -1) {
                    int lengthOffset = offset == 7 ? 26 : 28;
                    int nameOffset = offset == 7 ? 30 : 46;
                    int length = (bytes[i + lengthOffset] & 0xff) | ((bytes[i + lengthOffset + 1] & 0xff) << 8);
                    String name = new String(bytes, i + nameOffset, length, StandardCharsets.UTF_8);
                    if (targetName != null && !targetName.equals(name)) {
                        continue;
                    }
                    bytes[i + offset] = (byte) (set ? bytes[i + offset] | 8 : bytes[i + offset] & ~8);
                }
            }
        }
        Files.write(apk.toPath(), bytes);
    }

    @Test
    public void nonUtf8NameFallsBack() throws Exception {
        File apk = archive(Charset.forName("IBM437"), "caf\u00e9.txt", null);
        try (ZipFile zip = ZipUtils.openZipFile(apk)) {
            assertNotNull(zip.getEntry("caf\u00e9.txt"));
        }
    }

    @Test
    public void nonUtf8CommentFallsBackBeforeEnumeration() throws Exception {
        File apk = archive(Charset.forName("IBM437"), "plain.txt", "caf\u00e9");
        try (ZipFile zip = ZipUtils.openZipFile(apk)) {
            assertEquals("caf\u00e9", zip.entries().nextElement().getComment());
        }
    }

    @Test
    public void unflaggedUtf8KeepsHistoricalInterpretation() throws Exception {
        File apk = archive(StandardCharsets.UTF_8, "caf\u00e9.txt", "caf\u00e9");
        setUtf8Flag(apk, false);
        try (ZipFile zip = ZipUtils.openZipFile(apk)) {
            assertEquals("caf\u00e9", zip.getEntry("caf\u00e9.txt").getComment());
        }
    }

    @Test
    public void flaggedUtf8KeepsHistoricalInterpretation() throws Exception {
        File apk = archive(StandardCharsets.UTF_8, "\u65e5\u672c.txt", null);
        try (ZipFile zip = ZipUtils.openZipFile(apk)) {
            assertNotNull(zip.getEntry("\u65e5\u672c.txt"));
        }
    }

    @Test
    public void fallbackStillHonorsUtf8FlagInMixedArchive() throws Exception {
        File apk = tmp.newFile();
        Charset legacy = Charset.forName("IBM437");
        String utf8Name = "\u65e5\u672c.txt";
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(apk.toPath()), legacy)) {
            ZipEntry entry = new ZipEntry("legacy.txt");
            entry.setComment("caf\u00e9");
            out.putNextEntry(entry);
            out.write(1);
            out.closeEntry();
            out.putNextEntry(new ZipEntry(new String(utf8Name.getBytes(StandardCharsets.UTF_8), legacy)));
            out.write(2);
            out.closeEntry();
        }
        setUtf8Flag(apk, true, utf8Name);
        try (ZipFile zip = ZipUtils.openZipFile(apk)) {
            assertEquals("caf\u00e9", zip.getEntry("legacy.txt").getComment());
            assertNotNull(ZipUtils.getZipEntry(zip, utf8Name));
        }
        try (ZipRODirectory dir = new ZipRODirectory(apk);
                InputStream input = dir.getFileInput(utf8Name)) {
            assertEquals(2, input.read());
            assertEquals(-1, input.read());
        }
    }

    @Test
    public void invalidFlaggedUtf8IsNotAcceptedAsLegacy() throws Exception {
        File apk = archive(Charset.forName("IBM437"), "caf\u00e9.txt", null);
        setUtf8Flag(apk, true);
        try (ZipFile ignored = ZipUtils.openZipFile(apk)) {
            fail("Invalid flagged UTF-8 must still fail");
        } catch (IOException | IllegalArgumentException ex) {
            assertEquals("Original UTF-8 failure must be retained", 1, ex.getSuppressed().length);
        }
    }

    @Test
    public void invalidZipStructureDoesNotTriggerCharsetRetry() throws Exception {
        File apk = tmp.newFile();
        Files.write(apk.toPath(), new byte[] { 1, 2, 3 });
        try (ZipFile ignored = ZipUtils.openZipFile(apk)) {
            fail("Invalid ZIP must still fail");
        } catch (IOException ex) {
            assertEquals(0, ex.getSuppressed().length);
        }
    }

    @Test
    public void allSelectedDexEntriesDecodeWithLegacyMetadata() throws Exception {
        File apk = tmp.newFile();
        byte[] dex = SmaliTypeValidationTest.dexBytes("Lexample/Valid;");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(apk.toPath()),
                Charset.forName("IBM437"))) {
            for (String name : new String[] { "classes.dex", "classes2.dex" }) {
                ZipEntry entry = new ZipEntry(name);
                entry.setComment("caf\u00e9");
                out.putNextEntry(entry);
                out.write(dex);
                out.closeEntry();
            }
        }
        Config config = new Config("test");
        config.setJobs(1);
        config.setDecodeManifestMode(Config.DecodeMode.SKIP);
        config.setDecodeResMode(Config.DecodeMode.SKIP);
        File decoded = new File(tmp.getRoot(), "decoded");
        new ApkDecoder(apk, config).decode(decoded);
        assertTrue(new File(decoded, "smali/example/Valid.smali").isFile());
        assertTrue(new File(decoded, "smali_classes2/example/Valid.smali").isFile());

        config.setDecodeDexMode(Config.DecodeMode.RAW);
        File raw = new File(tmp.getRoot(), "raw");
        new ApkDecoder(apk, config).decode(raw);
        assertArrayEquals(dex, Files.readAllBytes(new File(raw, "classes.dex").toPath()));
        assertArrayEquals(dex, Files.readAllBytes(new File(raw, "classes2.dex").toPath()));
    }
}
