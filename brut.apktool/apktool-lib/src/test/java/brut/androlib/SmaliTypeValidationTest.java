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

import brut.androlib.exceptions.AndrolibException;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.file.Files;
import java.util.Collections;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;

public class SmaliTypeValidationTest {
    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    static byte[] dexBytes(String type) throws Exception {
        ImmutableClassDef clz = new ImmutableClassDef(type, 1, "Ljava/lang/Object;",
            Collections.emptyList(), null, Collections.emptySet(), Collections.emptyList(), Collections.emptyList());
        MemoryDataStore store = new MemoryDataStore();
        DexPool.writeTo(store, new ImmutableDexFile(Opcodes.forApi(15), Collections.singleton(clz)));
        return store.getData();
    }

    private File apk(byte[] dex) throws Exception {
        File apk = tmp.newFile("types.apk");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(apk.toPath()))) {
            out.putNextEntry(new ZipEntry("classes.dex"));
            out.write(dex);
            out.closeEntry();
        }
        return apk;
    }

    private Config config(Config.DecodeMode dexMode, int jobs) {
        Config config = new Config("test");
        config.setJobs(jobs);
        config.setDecodeDexMode(dexMode);
        config.setDecodeManifestMode(Config.DecodeMode.SKIP);
        config.setDecodeResMode(Config.DecodeMode.SKIP);
        return config;
    }

    private void assertInvalidTypeRejected(int jobs) throws Exception {
        File out = new File(tmp.getRoot(), "decoded");
        try {
            new ApkDecoder(apk(dexBytes("not-a-type")), config(Config.DecodeMode.DECODE, jobs)).decode(out);
            fail("Invalid type must not be accepted");
        } catch (AndrolibException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("Invalid type reference in classes.dex"));
            assertTrue(ex.getMessage(), ex.getMessage().contains("type index"));
            assertTrue(ex.getMessage(), ex.getMessage().contains("not-a-type"));
            assertFalse(new File(out, "smali").exists());
        }
    }

    @Test(timeout = 10000)
    public void invalidTypeIsReportedWithoutRecursion() throws Exception {
        assertInvalidTypeRejected(1);
    }

    @Test(timeout = 10000)
    public void invalidTypeIsReportedFromWorker() throws Exception {
        assertInvalidTypeRejected(2);
    }

    @Test
    public void validTypeStillProducesSmali() throws Exception {
        File out = new File(tmp.getRoot(), "decoded");
        new ApkDecoder(apk(dexBytes("Lexample/Valid;")), config(Config.DecodeMode.DECODE, 1)).decode(out);
        assertTrue(new File(out, "smali/example/Valid.smali").isFile());
    }

    @Test
    public void rawModeKeepsInvalidDexUnmodified() throws Exception {
        byte[] dex = dexBytes("not-a-type");
        File out = new File(tmp.getRoot(), "decoded");
        new ApkDecoder(apk(dex), config(Config.DecodeMode.RAW, 1)).decode(out);
        assertArrayEquals(dex, Files.readAllBytes(new File(out, "classes.dex").toPath()));
    }

    @Test
    public void skipModeDoesNotValidateInvalidTypes() throws Exception {
        File out = new File(tmp.getRoot(), "decoded");
        new ApkDecoder(apk(dexBytes("not-a-type")), config(Config.DecodeMode.SKIP, 1)).decode(out);
        assertFalse(new File(out, "smali").exists());
        assertFalse(new File(out, "classes.dex").exists());
    }
}
