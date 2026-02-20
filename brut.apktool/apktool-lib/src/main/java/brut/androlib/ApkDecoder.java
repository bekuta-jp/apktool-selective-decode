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
import brut.androlib.exceptions.InFileNotFoundException;
import brut.androlib.exceptions.OutDirExistsException;
import brut.androlib.meta.ApkInfo;
import brut.androlib.res.ResDecoder;
import brut.androlib.smali.SmaliDecoder;
import brut.common.Log;
import brut.directory.Directory;
import brut.directory.DirectoryException;
import brut.directory.ExtFile;
import brut.util.BackgroundWorker;
import brut.util.OS;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.io.FilenameUtils;

import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

public class ApkDecoder {
    private static final String TAG = ApkDecoder.class.getName();

    private static final Pattern NO_COMPRESS_EXT_PATTERN = Pattern.compile(
        "dex|arsc|so|jpg|jpeg|png|gif|wav|mp2|mp3|ogg|aac|mpg|mpeg|mid|midi|smf|jet|"
      + "rtttl|imy|xmf|mp4|m4a|m4v|3gp|3gpp|3g2|3gpp2|amr|awb|wma|wmv|webm|webp|mkv");

    private final ExtFile mApkFile;
    private final Config mConfig;
    private final AtomicReference<AndrolibException> mFirstError;

    private ApkInfo mApkInfo;
    private SmaliDecoder mSmaliDecoder;
    private ResDecoder mResDecoder;
    private BackgroundWorker mWorker;
    private int mDexHandledCount;
    private int mRawCopiedCount;
    private int mOriginalCopiedCount;
    private int mUnknownCopiedCount;
    private String mDexAction;
    private String mManifestAction;
    private String mResAction;

    public ApkDecoder(File apkFile, Config config) {
        mApkFile = new ExtFile(apkFile);
        mConfig = config;
        mFirstError = new AtomicReference<>();
        mDexHandledCount = 0;
        mRawCopiedCount = 0;
        mOriginalCopiedCount = 0;
        mUnknownCopiedCount = 0;
        mDexAction = "skip";
        mManifestAction = "skip";
        mResAction = "skip";
    }

    public void decode(File outDir) throws AndrolibException {
        if (!mConfig.isForced() && outDir.exists()) {
            throw new OutDirExistsException(outDir.getPath());
        }
        if (!mApkFile.isFile() || !mApkFile.canRead()) {
            throw new InFileNotFoundException(mApkFile.getPath());
        }
        if (mConfig.getJobs() > 1) {
            mWorker = new BackgroundWorker(mConfig.getJobs() - 1);
        }
        try {
            mApkInfo = new ApkInfo();
            mApkInfo.setVersion(mConfig.getVersion());
            mApkInfo.setApkFile(mApkFile);
            mSmaliDecoder = new SmaliDecoder(mApkFile, mConfig.isBaksmaliDebugMode());
            mResDecoder = new ResDecoder(mApkInfo, mConfig);

            OS.rmdir(outDir);
            OS.mkdir(outDir);

            Log.i(TAG, "Using Apktool " + mConfig.getVersion() + " on " + mApkFile.getName()
                     + (mWorker != null ? " with " + mConfig.getJobs() + " threads" : ""));

            decodeSources(outDir);
            decodeResources(outDir);
            decodeManifest(outDir);

            if (mWorker != null) {
                mWorker.waitForFinish();
                if (mFirstError.get() != null) {
                    throw mFirstError.get();
                }
            }

            copyOriginalFiles(outDir);
            copyRawFiles(outDir);
            copyUnknownFiles(outDir);
            writeApkInfo(outDir);
            logDecodeSummary();
        } finally {
            if (mWorker != null) {
                mWorker.shutdownNow();
            }
            try {
                mApkFile.close();
            } catch (DirectoryException ignored) {
            }
        }
    }

    @VisibleForTesting
    ApkInfo getApkInfo() {
        return mApkInfo;
    }

    private void decodeSources(File outDir) throws AndrolibException {
        if (!mApkInfo.hasSources()) {
            mDexAction = "skip (not found)";
            return;
        }

        Config.DecodeMode mode = getDexMode();
        mDexAction = formatMode(mode);
        if (mode == Config.DecodeMode.SKIP) {
            Log.i(TAG, "Skipping dex files...");
            return;
        }

        try {
            Directory in = mApkFile.getDirectory();
            boolean allSrc = mConfig.isDecodeSourcesFull();

            for (String fileName : in.getFiles(allSrc)) {
                if (allSrc ? !fileName.endsWith(".dex") : !ApkInfo.CLASSES_FILES_PATTERN.matcher(fileName).matches()) {
                    continue;
                }

                if (mode == Config.DecodeMode.RAW) {
                    copySourcesRaw(outDir, fileName);
                } else {
                    decodeSourcesSmali(outDir, fileName);
                }
                mDexHandledCount++;
            }
        } catch (DirectoryException ex) {
            throw new AndrolibException(ex);
        }
    }

    private void copySourcesRaw(File outDir, String fileName) throws AndrolibException {
        Log.i(TAG, "Copying raw " + fileName + "...");
        try {
            Directory in = mApkFile.getDirectory();

            in.copyToDir(outDir, fileName);
        } catch (DirectoryException ex) {
            throw new AndrolibException(ex);
        }
    }

    private void decodeSourcesSmali(File outDir, String fileName) throws AndrolibException {
        if (mWorker != null) {
            mWorker.submit(() -> {
                if (mFirstError.get() == null) {
                    try {
                        decodeSourcesSmaliJob(outDir, fileName);
                    } catch (AndrolibException ex) {
                        mFirstError.compareAndSet(null, ex);
                    }
                }
            });
        } else {
            decodeSourcesSmaliJob(outDir, fileName);
        }
    }

    private void decodeSourcesSmaliJob(File outDir, String fileName) throws AndrolibException {
        Log.i(TAG, "Baksmaling " + fileName + "...");
        mSmaliDecoder.decode(fileName, outDir);
    }

    private void decodeResources(File outDir) throws AndrolibException {
        if (!mApkInfo.hasResources()) {
            mResAction = "skip (not found)";
            return;
        }

        Config.DecodeMode mode = getResMode();
        mResAction = formatMode(mode);
        switch (mode) {
            case DECODE:
                mResDecoder.decodeResources(outDir);
                break;
            case RAW:
                copyResourcesRaw(outDir);
                break;
            case SKIP:
                Log.i(TAG, "Skipping resources...");
                break;
            default:
                throw new IllegalStateException("Unexpected resources mode: " + mode);
        }
    }

    private void copyResourcesRaw(File outDir) throws AndrolibException {
        Log.i(TAG, "Copying raw resources.arsc...");
        try {
            Directory in = mApkFile.getDirectory();

            in.copyToDir(outDir, "resources.arsc");
        } catch (DirectoryException ex) {
            throw new AndrolibException(ex);
        }
    }

    private void decodeManifest(File outDir) throws AndrolibException {
        if (!mApkInfo.hasManifest()) {
            mManifestAction = "skip (not found)";
            return;
        }

        Config.DecodeMode mode = getManifestMode();
        mManifestAction = formatMode(mode);
        switch (mode) {
            case DECODE:
                mResDecoder.decodeManifest(outDir);
                break;
            case RAW:
                copyManifestRaw(outDir);
                break;
            case SKIP:
                Log.i(TAG, "Skipping AndroidManifest.xml...");
                break;
            default:
                throw new IllegalStateException("Unexpected manifest mode: " + mode);
        }
    }

    private void copyManifestRaw(File outDir) throws AndrolibException {
        Log.i(TAG, "Copying raw AndroidManifest.xml...");
        try {
            Directory in = mApkFile.getDirectory();

            in.copyToDir(outDir, "AndroidManifest.xml");
        } catch (DirectoryException ex) {
            throw new AndrolibException(ex);
        }
    }

    private void copyRawFiles(File outDir) throws AndrolibException {
        try {
            Directory in = mApkFile.getDirectory();
            Set<String> dexFiles = mSmaliDecoder.getDexFiles();
            Map<String, String> resFileMap = mResDecoder.getResFileMap();
            boolean noAssets = mConfig.isDecodeAssetsNone();

            for (String dirName : ApkInfo.RAW_DIRS) {
                if (!in.containsDir(dirName) || (noAssets && dirName.equals("assets"))) {
                    continue;
                }

                Log.i(TAG, "Copying " + dirName + "...");
                for (String fileName : in.getDir(dirName).getFiles(true)) {
                    fileName = dirName + in.separator + fileName;
                    if (!ApkInfo.ORIGINAL_FILES_PATTERN.matcher(fileName).matches()
                            && !dexFiles.contains(fileName) && !resFileMap.containsKey(fileName)) {
                        in.copyToDir(outDir, fileName);
                        mRawCopiedCount++;
                    }
                }
            }
        } catch (DirectoryException ex) {
            throw new AndrolibException(ex);
        }
    }

    private void copyOriginalFiles(File outDir) throws AndrolibException {
        File originalDir = new File(outDir, "original");

        Log.i(TAG, "Copying original files...");
        try {
            Directory in = mApkFile.getDirectory();
            boolean skipManifest = getManifestMode() == Config.DecodeMode.SKIP;

            for (String fileName : in.getFiles(true)) {
                if (ApkInfo.ORIGINAL_FILES_PATTERN.matcher(fileName).matches()) {
                    if (skipManifest && fileName.equals("AndroidManifest.xml")) {
                        continue;
                    }
                    in.copyToDir(originalDir, fileName);
                    mOriginalCopiedCount++;
                }
            }
        } catch (DirectoryException ex) {
            throw new AndrolibException(ex);
        }
    }

    private void copyUnknownFiles(File outDir) throws AndrolibException {
        File unknownDir = new File(outDir, "unknown");

        Log.i(TAG, "Copying unknown files...");
        try {
            Directory in = mApkFile.getDirectory();
            Set<String> dexFiles = mSmaliDecoder.getDexFiles();
            Map<String, String> resFileMap = mResDecoder.getResFileMap();
            boolean skipRes = getResMode() == Config.DecodeMode.SKIP;

            for (String fileName : in.getFiles(true)) {
                if (skipRes && fileName.startsWith("res/")) {
                    continue;
                }
                if (!ApkInfo.STANDARD_FILES_PATTERN.matcher(fileName).matches() && !dexFiles.contains(fileName)
                        && !resFileMap.containsKey(fileName)) {
                    in.copyToDir(unknownDir, fileName);
                    mUnknownCopiedCount++;
                }
            }
        } catch (DirectoryException ex) {
            throw new AndrolibException(ex);
        }
    }

    private void writeApkInfo(File outDir) throws AndrolibException {
        // If we did not decode the manifest, store the inferred dex opcode API level.
        if (!mApkInfo.hasManifest() || getManifestMode() != Config.DecodeMode.DECODE) {
            int apiLevel = mSmaliDecoder.getInferredApiLevel();
            if (apiLevel > 0) {
                mApkInfo.getSdkInfo().setMinSdkVersion(Integer.toString(apiLevel));
            }
        }

        // Record uncompressed files.
        try {
            Directory in = mApkFile.getDirectory();
            Map<String, String> resFileMap = mResDecoder.getResFileMap();
            Set<String> uncompressedExts = new HashSet<>();
            Set<String> uncompressedFiles = new HashSet<>();

            for (String fileName : in.getFiles(true)) {
                if (in.getCompressionLevel(fileName) == 0) {
                    String ext;
                    if (in.getSize(fileName) > 0 && !(ext = FilenameUtils.getExtension(fileName)).isEmpty()
                            && NO_COMPRESS_EXT_PATTERN.matcher(ext).matches()) {
                        uncompressedExts.add(ext);
                    } else {
                        uncompressedFiles.add(resFileMap.getOrDefault(fileName, fileName));
                    }
                }
            }

            // Exclude files with an already recorded extenstion.
            if (!uncompressedExts.isEmpty() && !uncompressedFiles.isEmpty()) {
                Iterator<String> it = uncompressedFiles.iterator();
                while (it.hasNext()) {
                    String fileName = it.next();
                    String ext = FilenameUtils.getExtension(fileName);
                    if (uncompressedExts.contains(ext)) {
                        it.remove();
                    }
                }
            }

            // Update apk info.
            List<String> doNotCompress = mApkInfo.getDoNotCompress();
            if (!uncompressedExts.isEmpty()) {
                List<String> uncompressedExtsList = new ArrayList<>(uncompressedExts);
                uncompressedExtsList.sort(null);
                doNotCompress.addAll(uncompressedExtsList);
            }
            if (!uncompressedFiles.isEmpty()) {
                List<String> uncompressedFilesList = new ArrayList<>(uncompressedFiles);
                uncompressedFilesList.sort(null);
                doNotCompress.addAll(uncompressedFilesList);
            }
        } catch (DirectoryException ex) {
            throw new AndrolibException(ex);
        }

        // Serialize apk info to file.
        mApkInfo.save(outDir);
    }

    private Config.DecodeMode getDexMode() {
        Config.DecodeMode mode = mConfig.getDecodeDexMode();
        if (mode != Config.DecodeMode.AUTO) {
            return mode;
        }
        return mConfig.isDecodeSourcesNone() ? Config.DecodeMode.RAW : Config.DecodeMode.DECODE;
    }

    private Config.DecodeMode getManifestMode() {
        Config.DecodeMode mode = mConfig.getDecodeManifestMode();
        if (mode != Config.DecodeMode.AUTO) {
            return mode;
        }
        return mConfig.isDecodeResourcesNone() ? Config.DecodeMode.RAW : Config.DecodeMode.DECODE;
    }

    private Config.DecodeMode getResMode() {
        Config.DecodeMode mode = mConfig.getDecodeResMode();
        if (mode != Config.DecodeMode.AUTO) {
            return mode;
        }
        return mConfig.isDecodeResourcesFull() ? Config.DecodeMode.DECODE : Config.DecodeMode.RAW;
    }

    private String formatMode(Config.DecodeMode mode) {
        switch (mode) {
            case DECODE:
                return "decode";
            case RAW:
                return "raw";
            case SKIP:
                return "skip";
            default:
                return "auto";
        }
    }

    private void logDecodeSummary() {
        Log.i(TAG, String.format(
            "Decode summary: dex=%s (%d files), manifest=%s, res=%s, copied(original=%d, raw=%d, unknown=%d)",
            mDexAction, mDexHandledCount, mManifestAction, mResAction,
            mOriginalCopiedCount, mRawCopiedCount, mUnknownCopiedCount));
    }
}
