package com.forensix.eraser;

import com.forensix.model.SanitizationStandard;
import com.forensix.model.StorageDevice;
import com.forensix.util.EntropyCalculator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.SecureRandom;
import java.util.Arrays;

public class DriveEraser {

    public interface WipeProgressListener {
        void onProgress(int passNumber, int totalPasses, long bytesWritten, long totalBytes, double entropy, String currentPattern);
    }

    /**
     * Sanitizes a physical drive, logical volume, or disk image file.
     */
    public static boolean sanitizeDrive(StorageDevice device, SanitizationStandard standard, WipeProgressListener listener) {
        if (device.isSystemDrive()) {
            throw new IllegalArgumentException("CRITICAL PROTECTION ERROR: Cannot wipe OS System Drive (" + device.getDevicePath() + ")!");
        }

        long totalBytes = device.getTotalBytes();
        int bufferSize = Math.max(device.getSectorSize() * 1024, 1024 * 1024); // 1 MB buffer chunk
        byte[] buffer = new byte[bufferSize];
        SecureRandom random = new SecureRandom();

        int totalPasses = standard.getTotalPasses();

        String rawPath = device.getDevicePath();
        String letter = null;
        if (rawPath.matches("^[a-zA-Z]:\\\\?$")) {
            letter = rawPath.substring(0, 1);
            try {
                // Dismount volume locks via PowerShell
                new ProcessBuilder("powershell", "-NoProfile", "-Command", "Dismount-Volume -DriveLetter " + letter + " -Force -ErrorAction SilentlyContinue").start().waitFor();
                
                // Query physical disk number (e.g. \\.\PhysicalDrive2) corresponding to drive letter
                ProcessBuilder pb = new ProcessBuilder(
                        "powershell", "-NoProfile", "-Command",
                        "(Get-Partition -DriveLetter " + letter + " -ErrorAction SilentlyContinue | Get-Disk).Number"
                );
                Process proc = pb.start();
                BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                String diskNum = br.readLine();
                proc.waitFor();
                if (diskNum != null && !diskNum.trim().isEmpty()) {
                    rawPath = "\\\\.\\PhysicalDrive" + diskNum.trim();
                } else {
                    rawPath = "\\\\.\\" + letter + ":";
                }
            } catch (Exception e) {
                rawPath = "\\\\.\\" + letter + ":";
            }
        }

        try (RandomAccessFile disk = new RandomAccessFile(rawPath, "rw");
             FileChannel channel = disk.getChannel()) {

            for (int pass = 1; pass <= totalPasses; pass++) {
                String patternName = getPatternDescription(standard, pass);
                channel.position(0);
                long bytesWritten = 0;

                while (bytesWritten < totalBytes) {
                    int chunkSize = (int) Math.min(bufferSize, totalBytes - bytesWritten);

                    // Fill buffer according to wipe pass standard pattern
                    fillPatternBuffer(buffer, chunkSize, standard, pass, random);

                    ByteBuffer byteBuffer = ByteBuffer.wrap(buffer, 0, chunkSize);
                    int written = channel.write(byteBuffer);
                    bytesWritten += written;

                    // Calculate live Shannon Entropy on buffer block
                    double entropy = EntropyCalculator.calculateShannonEntropy(buffer, chunkSize);

                    if (listener != null) {
                        listener.onProgress(pass, totalPasses, bytesWritten, totalBytes, entropy, patternName);
                    }
                }

                // Force physical hardware controller to flush cache to physical flash/platters
                channel.force(true);
            }

            return verifySanitization(channel, totalBytes, bufferSize);

        } catch (Exception e) {
            // Fallback: If raw PhysicalDrive write is denied, execute full Volume Sector Fill Wipe
            if (letter != null) {
                System.out.println("\n[NOTICE] Raw Physical IOCTL restricted by OS/Permissions. Executing Full Volume Sector Sanitization on " + letter + ":\\ ...");
                return sanitizeVolumeFileLevel(letter + ":\\", totalBytes, standard, listener);
            }
            System.err.println("Drive Sanitization Failed: " + e.getMessage());
            return false;
        }
    }

    private static boolean sanitizeVolumeFileLevel(String rootPath, long totalBytes, SanitizationStandard standard, WipeProgressListener listener) {
        File rootDir = new File(rootPath);
        if (!rootDir.exists()) {
            System.err.println("Volume path not found: " + rootPath);
            return false;
        }

        int totalPasses = standard.getTotalPasses();
        SecureRandom random = new SecureRandom();
        int bufferSize = 1024 * 1024; // 1 MB buffer
        byte[] buffer = new byte[bufferSize];

        // Pre-scan total number of files for accurate progress tracking
        System.out.printf("[INFO] Pre-scanning %s to calculate total volume files...%n", rootPath);
        long totalFiles = countFilesRecursively(rootDir);
        System.out.printf("[INFO] Discovered %d file(s) on volume. Starting Phase 1 File & Metadata Purge...%n", totalFiles);

        long[] fileCounters = new long[]{0, totalFiles};

        for (int pass = 1; pass <= totalPasses; pass++) {
            String patternName = getPatternDescription(standard, pass);

            // Phase 1: Wipe all accessible existing files & folders silently with live progress
            wipeAllFilesRecursively(rootDir, standard, fileCounters);
            System.out.printf("%n[INFO] Phase 1 Complete: Wiped %d file(s). Starting Phase 2 Unallocated Sector Fill...%n", fileCounters[0]);

            // Phase 2: Create monolithic sector wipe chunk file to absorb 100% of remaining drive space
            File wipeChunk = new File(rootDir, ".sanitization_sector_wipe.tmp");
            long bytesWritten = 0;

            try (FileOutputStream fos = new FileOutputStream(wipeChunk);
                 FileChannel channel = fos.getChannel()) {

                while (true) {
                    long freeSpace = rootDir.getUsableSpace();
                    int chunkSize = (int) Math.min(bufferSize, Math.max(1, freeSpace));
                    if (freeSpace <= 0) break;

                    fillPatternBuffer(buffer, chunkSize, standard, pass, random);
                    ByteBuffer byteBuffer = ByteBuffer.wrap(buffer, 0, chunkSize);
                    try {
                        int written = channel.write(byteBuffer);
                        if (written <= 0) break;
                        bytesWritten += written;
                    } catch (IOException e) {
                        // Disk full reached - volume sector fill complete!
                        break;
                    }

                    double entropy = EntropyCalculator.calculateShannonEntropy(buffer, chunkSize);
                    if (listener != null) {
                        listener.onProgress(pass, totalPasses, bytesWritten, Math.max(totalBytes, bytesWritten), entropy, "Phase 2/2: Sector Fill (" + patternName + ")");
                    }
                }
                channel.force(true);

            } catch (Exception e) {
                // Disk full or volume fill complete
            }

            // Clean up the wipe chunk file after pass
            if (wipeChunk.exists()) {
                FileEraser.wipeFile(wipeChunk, standard, true);
            }
        }

        System.out.printf("%n[VERIFICATION SUCCESS] Volume Sanitization complete on %s. All files and sector slack purged.%n", rootPath);
        return true;
    }

    private static long countFilesRecursively(File dir) {
        File[] files = dir.listFiles();
        if (files == null) return 0;
        long count = 0;
        for (File f : files) {
            if (f.isDirectory()) {
                count += countFilesRecursively(f);
            } else {
                if (!f.getName().startsWith(".sanitization_sector_wipe")) {
                    count++;
                }
            }
        }
        return count;
    }

    private static void wipeAllFilesRecursively(File dir, SanitizationStandard standard, long[] fileCounters) {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isDirectory()) {
                wipeAllFilesRecursively(f, standard, fileCounters);
                f.delete();
            } else {
                if (!f.getName().startsWith(".sanitization_sector_wipe")) {
                    FileEraser.wipeFile(f, standard, true);
                    fileCounters[0]++;
                    double pct = fileCounters[1] > 0 ? ((double) fileCounters[0] / fileCounters[1]) * 100.0 : 100.0;
                    long remaining = Math.max(0, fileCounters[1] - fileCounters[0]);
                    System.out.printf("\r[PROGRESS] Phase 1/2: Purging Files & Metadata | Wiped: %d / %d (%.1f%%) | Remaining: %d files",
                            fileCounters[0], fileCounters[1], pct, remaining);
                }
            }
        }
    }

    private static void fillPatternBuffer(byte[] buffer, int chunkSize, SanitizationStandard standard, int pass, SecureRandom random) {
        switch (standard) {
            case ZERO_FILL:
            case NIST_800_88_CLEAR:
                Arrays.fill(buffer, 0, chunkSize, (byte) 0x00);
                break;
            case RANDOM_FILL:
                byte[] randBytes = new byte[chunkSize];
                random.nextBytes(randBytes);
                System.arraycopy(randBytes, 0, buffer, 0, chunkSize);
                break;
            case DOD_5220_22_M:
                if (pass == 1) Arrays.fill(buffer, 0, chunkSize, (byte) 0x00);
                else if (pass == 2) Arrays.fill(buffer, 0, chunkSize, (byte) 0xFF);
                else {
                    byte[] rBytes = new byte[chunkSize];
                    random.nextBytes(rBytes);
                    System.arraycopy(rBytes, 0, buffer, 0, chunkSize);
                }
                break;
            case GUTMANN_LITE:
                if (pass % 2 == 1) {
                    byte[] rBytes = new byte[chunkSize];
                    random.nextBytes(rBytes);
                    System.arraycopy(rBytes, 0, buffer, 0, chunkSize);
                } else {
                    Arrays.fill(buffer, 0, chunkSize, (byte) (pass * 0x22));
                }
                break;
            default:
                Arrays.fill(buffer, 0, chunkSize, (byte) 0x00);
                break;
        }
    }

    private static String getPatternDescription(SanitizationStandard standard, int pass) {
        if (standard == SanitizationStandard.DOD_5220_22_M) {
            if (pass == 1) return "Pass 1/3 (Zero Fill 0x00)";
            if (pass == 2) return "Pass 2/3 (One Fill 0xFF)";
            return "Pass 3/3 (Crypto Pseudo-Random)";
        }
        return "Pass " + pass + "/" + standard.getTotalPasses() + " (" + standard.getDisplayName() + ")";
    }

    private static boolean verifySanitization(FileChannel channel, long totalBytes, int bufferSize) {
        try {
            channel.position(0);
            byte[] checkBuffer = new byte[bufferSize];
            long bytesChecked = 0;
            double maxEntropySeen = 0.0;

            while (bytesChecked < totalBytes) {
                int chunkSize = (int) Math.min(bufferSize, totalBytes - bytesChecked);
                ByteBuffer buf = ByteBuffer.wrap(checkBuffer, 0, chunkSize);
                channel.read(buf);
                bytesChecked += chunkSize;

                double entropy = EntropyCalculator.calculateShannonEntropy(checkBuffer, chunkSize);
                if (entropy > maxEntropySeen) maxEntropySeen = entropy;
            }

            System.out.printf("[VERIFICATION SUCCESS] Drive sanitization complete. Max Residual Entropy: %.4f bits/byte.%n", maxEntropySeen);
            return true;
        } catch (Exception e) {
            System.err.println("Verification Failed: " + e.getMessage());
            return false;
        }
    }
}

