package com.forensix.carver;

import com.forensix.model.CarvedFile;
import com.forensix.util.EntropyCalculator;
import com.forensix.util.HashUtil;

import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class FileCarver {

    public interface CarverProgressListener {
        void onProgress(long bytesScanned, long totalBytes, int filesFound);
    }

    /**
     * Carves raw sector stream or disk image file for deleted files.
     */
    public static List<CarvedFile> carveDevice(String sourcePath, File outputDir, CarverProgressListener listener) {
        List<CarvedFile> carvedFiles = new ArrayList<>();
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        List<FileSignature> signatures = FileSignature.getStandardForensicSignatures();
        int sectorSize = 512;
        int readChunkSize = 1024 * 1024; // 1 MB scan buffer

        try (RandomAccessFile rawDisk = new RandomAccessFile(sourcePath, "r");
             FileChannel channel = rawDisk.getChannel()) {

            long totalBytes = channel.size();
            long currentPosition = 0;
            byte[] scanBuffer = new byte[readChunkSize];

            int fileCount = 0;

            while (currentPosition < totalBytes) {
                int bytesToRead = (int) Math.min(scanBuffer.length, totalBytes - currentPosition);
                ByteBuffer buffer = ByteBuffer.wrap(scanBuffer, 0, bytesToRead);
                channel.position(currentPosition);
                channel.read(buffer);

                // Scan byte by byte for signature header matches
                for (int i = 0; i < bytesToRead - 16; i++) {
                    for (FileSignature sig : signatures) {
                        if (matchBytes(scanBuffer, i, sig.getHeaderMagic())) {
                            long absoluteStartOffset = currentPosition + i;
                            long startLba = absoluteStartOffset / sectorSize;

                            // Extract carved file payload
                            CarvedFile carved = extractFilePayload(channel, absoluteStartOffset, startLba, sig, outputDir, fileCount + 1);
                            if (carved != null) {
                                carvedFiles.add(carved);
                                fileCount++;
                                i += Math.min(carved.getLengthBytes(), 1024); // Advance scan index
                            }
                        }
                    }
                }

                currentPosition += readChunkSize - 4096; // Overlap buffer to prevent missing signatures across boundaries
                if (listener != null) {
                    listener.onProgress(currentPosition, totalBytes, fileCount);
                }
            }

        } catch (Exception e) {
            System.err.println("File Carving Error: " + e.getMessage());
            e.printStackTrace();
        }

        return carvedFiles;
    }

    private static CarvedFile extractFilePayload(FileChannel channel, long startOffset, long startLba,
                                                FileSignature sig, File outputDir, int count) {
        try {
            long maxRead = Math.min(sig.getMaxSizeBytes(), channel.size() - startOffset);
            byte[] payload = new byte[(int) maxRead];

            channel.position(startOffset);
            ByteBuffer buf = ByteBuffer.wrap(payload);
            int read = channel.read(buf);

            // Find Footer Signature offset
            int footerOffset = findByteSequence(payload, read, sig.getFooterMagic());
            int extractedLength;
            boolean isIntact = false;

            if (footerOffset != -1) {
                extractedLength = footerOffset + sig.getFooterMagic().length;
                isIntact = true;
            } else {
                // Fallback size estimate if footer missing (e.g. truncated file)
                extractedLength = (int) Math.min(read, 256 * 1024); // default 256KB sample
            }

            byte[] finalFileBytes = new byte[extractedLength];
            System.arraycopy(payload, 0, finalFileBytes, 0, extractedLength);

            // Calculate Forensic Cryptographic Hash
            String sha256 = HashUtil.calculateSHA256(finalFileBytes);

            // Calculate Confidence Score based on structural intactness + Shannon Entropy
            double entropy = EntropyCalculator.calculateShannonEntropy(finalFileBytes, finalFileBytes.length);
            double confidence = isIntact ? 0.95 : 0.45;
            if (entropy > 2.0 && entropy < 7.8) {
                confidence += 0.04; // Normal file entropy range
            }

            String id = String.format("CARVE_%04d", count);
            String fileName = id + "_" + sig.getName().replace(" ", "_") + sig.getExtension();
            File outFile = new File(outputDir, fileName);

            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                fos.write(finalFileBytes);
            }

            CarvedFile carved = new CarvedFile(
                    id, sig.getName(), sig.getExtension(), startLba, startOffset,
                    extractedLength, Math.min(confidence, 0.99), sha256, isIntact
            );
            carved.setOutputFilePath(outFile.getAbsolutePath());

            System.out.printf("[CARVED] Extracted %s (%s) @ Offset 0x%X [Score: %.1f%%]%n",
                    fileName, carved.getFormattedSize(), startOffset, confidence * 100);

            return carved;

        } catch (Exception e) {
            return null;
        }
    }

    private static boolean matchBytes(byte[] buffer, int offset, byte[] target) {
        if (offset + target.length > buffer.length) return false;
        for (int i = 0; i < target.length; i++) {
            if (buffer[offset + i] != target[i]) return false;
        }
        return true;
    }

    private static int findByteSequence(byte[] buffer, int limit, byte[] target) {
        if (target == null || target.length == 0) return -1;
        for (int i = 0; i <= limit - target.length; i++) {
            if (matchBytes(buffer, i, target)) return i;
        }
        return -1;
    }
}
