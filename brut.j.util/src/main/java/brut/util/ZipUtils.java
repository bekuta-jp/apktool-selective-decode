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
package brut.util;

import brut.common.Log;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.function.Predicate;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public final class ZipUtils {
    private static final String TAG = "";

    private ZipUtils() {
        // Private constructor for utility class.
    }

    /**
     * Prefer the historical UTF-8 interpretation, including for entries without the UTF-8 flag.
     * Retry with the ZIP legacy charset only when metadata cannot be decoded. ZipFile still
     * enforces UTF-8 for flagged entries. Payload corruption and unrelated I/O errors are fatal.
     */
    public static ZipFile openZipFile(File file) throws IOException {
        try {
            return openZipFile(file, StandardCharsets.UTF_8);
        } catch (IOException | IllegalArgumentException ex) {
            if (!isMetadataEncodingError(ex)) {
                throw ex;
            }
            try {
                ZipFile zip = openZipFile(file, Charset.forName("IBM437"));
                Log.w(TAG, "Reading ZIP metadata without the UTF-8 flag as IBM437: %s (%s)", file, ex.getMessage());
                return zip;
            } catch (IOException | IllegalArgumentException fallbackError) {
                fallbackError.addSuppressed(ex);
                throw fallbackError;
            }
        }
    }

    private static ZipFile openZipFile(File file, Charset charset) throws IOException {
        ZipFile zip = new ZipFile(file, charset);
        try {
            // Some JDKs decode comments/names lazily. Validate the whole central directory
            // before returning, so callers never start work with a partly decoded directory.
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                entries.nextElement();
            }
            return zip;
        } catch (RuntimeException | Error ex) {
            try {
                zip.close();
            } catch (IOException closeError) {
                ex.addSuppressed(closeError);
            }
            throw ex;
        }
    }

    private static boolean isMetadataEncodingError(Exception ex) {
        for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
            if (cause instanceof CharacterCodingException) {
                return true;
            }
        }
        String message = ex.getMessage();
        // JDK 8 may omit the CharacterCodingException cause; newer JDKs reject names at open.
        return message != null && ((ex instanceof ZipException
                && message.equals("invalid CEN header (bad entry name)"))
            || (ex instanceof IllegalArgumentException
                && (message.startsWith("MALFORMED[") || message.startsWith("UNMAPPABLE["))));
    }

    public static ZipEntry getZipEntry(ZipFile zip, String name) {
        try {
            ZipEntry entry = zip.getEntry(name);
            if (entry != null) {
                return entry;
            }
        } catch (IllegalArgumentException ex) {
            if (!isMetadataEncodingError(ex)) {
                throw ex;
            }
        }
        // Older JDKs encode lookup names with the archive charset even for UTF-8-flagged
        // entries. Enumeration decodes each entry with its own flag. Return that actual
        // entry so getInputStream also sees the flag instead of a synthetic ZipEntry.
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            if (entry.getName().equals(name)) {
                return entry;
            }
        }
        return null;
    }

    public static void zipDir(File dir, ZipOutputStream out, Collection<String> doNotCompress) throws IOException {
        zipDir(dir, null, out, doNotCompress);
    }

    public static void zipDir(File baseDir, String dirName, ZipOutputStream out, Collection<String> doNotCompress)
            throws IOException {
        File dir;
        if (dirName != null && !dirName.isEmpty()) {
            dir = new File(baseDir, dirName);
        } else {
            dir = baseDir;
        }
        if (!dir.isDirectory()) {
            return;
        }

        for (File file : dir.listFiles()) {
            String fileName = baseDir.toPath().relativize(file.toPath()).toString();

            if (file.isDirectory()) {
                zipDir(baseDir, fileName, out, doNotCompress);
            } else if (file.isFile()) {
                zipFile(baseDir, fileName, out, (doNotCompress != null && !doNotCompress.isEmpty())
                    ? entryName -> doNotCompress.contains(entryName)
                                || doNotCompress.contains(FilenameUtils.getExtension(entryName))
                    : entryName -> false);
            }
        }
    }

    public static void zipFile(File baseDir, String fileName, ZipOutputStream out, boolean doNotCompress)
            throws IOException {
        zipFile(baseDir, fileName, out, entryName -> doNotCompress);
    }

    private static void zipFile(File baseDir, String fileName, ZipOutputStream out, Predicate<String> doNotCompress)
            throws IOException {
        try {
            fileName = BrutIO.sanitizePath(baseDir, fileName);
            if (fileName.isEmpty()) {
                return;
            }

            File file = new File(baseDir, fileName);
            if (!file.isFile()) {
                return;
            }

            String entryName = FilenameUtils.separatorsToUnix(fileName);
            ZipEntry zipEntry = new ZipEntry(entryName);

            if (doNotCompress.test(entryName)) {
                zipEntry.setMethod(ZipEntry.STORED);
                zipEntry.setSize(file.length());
                try (InputStream in = Files.newInputStream(file.toPath())) {
                    CRC32 crc = BrutIO.calculateCrc(in);
                    zipEntry.setCrc(crc.getValue());
                }
            } else {
                zipEntry.setMethod(ZipEntry.DEFLATED);
            }

            out.putNextEntry(zipEntry);
            try (InputStream in = Files.newInputStream(file.toPath())) {
                IOUtils.copy(in, out);
            }
            out.closeEntry();
        } catch (InvalidPathException ex) {
            Log.w(TAG, "Skipping file %s (%s)", fileName, ex.getMessage());
        }
    }
}
