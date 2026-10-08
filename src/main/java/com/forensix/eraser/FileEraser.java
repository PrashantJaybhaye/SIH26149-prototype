package com.forensix.eraser;

import com.forensix.model.SanitizationStandard;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.SecureRandom;
import java.nio.file.Files;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;

public class FileEraser {

    /**
     * Wipes a target file, scrubs file content + slack space, resets timestamps, and unlinks it.
     */
    public static boolean wipeFile(File file, SanitizationStandard standard) {
        return wipeFile(file, standard, false);
    }

    /**
     * Wipes a target file, scrubs file content + slack space, resets timestamps, and unlinks it.
     */
    public static boolean wipeFile(File file, SanitizationStandard standard, boolean quiet) {
        if (!file.exists() || !file.isFile()) {
            if (!quiet) System.err.println("File does not exist or is not a regular file: " + file.getAbsolutePath());
            return false;
        }

        long fileLength = file.length();
        int clusterSize = 4096; // Standard 4KB cluster boundary
        long allocatedSize = ((fileLength + clusterSize - 1) / clusterSize) * clusterSize;
        long slackSpaceBytes = allocatedSize - fileLength;

        SecureRandom random = new SecureRandom();

        try {
            // 1. Multi-pass overwrite of actual file data bytes
            try (RandomAccessFile raf = new RandomAccessFile(file, "rw");
                 FileChannel channel = raf.getChannel()) {

                int totalPasses = standard.getTotalPasses();
                byte[] buffer = new byte[8192];

                for (int pass = 1; pass <= totalPasses; pass++) {
                    channel.position(0);
                    long written = 0;

                    while (written < fileLength) {
                        int chunkSize = (int) Math.min(buffer.length, fileLength - written);
                        fillPattern(buffer, chunkSize, standard, pass, random);

                        ByteBuffer byteBuffer = ByteBuffer.wrap(buffer, 0, chunkSize);
                        written += channel.write(byteBuffer);
                    }

                    // 2. Scrub File Slack Space (up to the allocated cluster boundary)
                    if (slackSpaceBytes > 0) {
                        byte[] slackBuffer = new byte[(int) slackSpaceBytes];
                        Arrays.fill(slackBuffer, (byte) 0x00);
                        channel.write(ByteBuffer.wrap(slackBuffer));
                    }

                    channel.force(true); // Flush hardware buffers
                }
            }

            // 3. Metadata & Timestamps Scrubbing (Reset Creation/Modification times to epoch 1970)
            FileTime epoch = FileTime.fromMillis(0);
            Files.setLastModifiedTime(file.toPath(), epoch);

            // 4. Rename File to random junk before deleting (to destroy MFT/Directory entry filename traces)
            File junkFile = new File(file.getParent(), "scramble_" + System.currentTimeMillis() + "_" + random.nextInt(99999) + ".tmp");
            boolean renamed = file.renameTo(junkFile);

            // 5. Unlink/Delete File
            File targetToDelete = renamed ? junkFile : file;
            boolean deleted = targetToDelete.delete();

            if (!quiet) {
                System.out.printf("[FILE ERASED] %s (Size: %d bytes, Slack Scrubbed: %d bytes)%n",
                        file.getName(), fileLength, slackSpaceBytes);
            }
            return deleted;

        } catch (Exception e) {
            if (!quiet) System.err.println("Failed to securely wipe file: " + e.getMessage());
            return false;
        }
    }

    private static void fillPattern(byte[] buffer, int len, SanitizationStandard standard, int pass, SecureRandom random) {
        if (standard == SanitizationStandard.ZERO_FILL || standard == SanitizationStandard.NIST_800_88_CLEAR) {
            Arrays.fill(buffer, 0, len, (byte) 0x00);
        } else {
            byte[] rand = new byte[len];
            random.nextBytes(rand);
            System.arraycopy(rand, 0, buffer, 0, len);
        }
    }
}
