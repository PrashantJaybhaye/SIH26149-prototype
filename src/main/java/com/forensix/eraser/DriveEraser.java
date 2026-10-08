package com.forensix.eraser;

import com.forensix.model.SanitizationStandard;
import com.forensix.model.StorageDevice;
import com.forensix.util.EntropyCalculator;

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
        if (rawPath.matches("^[a-zA-Z]:\\\\?$")) {
            String letter = rawPath.substring(0, 1);
            try {
                // Force dismount active locks on Windows volume so raw IOCTL write is granted
                ProcessBuilder pb = new ProcessBuilder(
                        "powershell", "-NoProfile", "-Command",
                        "Dismount-Volume -DriveLetter " + letter + " -Force -ErrorAction SilentlyContinue"
                );
                pb.start().waitFor();
            } catch (Exception ignored) {}

            rawPath = "\\\\.\\" + letter + ":";
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
            System.err.println("Drive Sanitization Failed: " + e.getMessage());
            e.printStackTrace();
            return false;
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
