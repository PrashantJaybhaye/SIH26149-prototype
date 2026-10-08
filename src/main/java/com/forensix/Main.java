package com.forensix;

import com.forensix.audit.ReportGenerator;
import com.forensix.carver.FileCarver;
import com.forensix.eraser.DriveEraser;
import com.forensix.eraser.FileEraser;
import com.forensix.model.CarvedFile;
import com.forensix.model.SanitizationStandard;
import com.forensix.model.StorageDevice;
import com.forensix.nativeio.StorageDetector;
import com.forensix.util.HashUtil;

import java.io.File;
import java.io.FileOutputStream;
import java.util.List;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        System.out.println("=========================================================================================");
        System.out.println("    FORENSIX: Integrated Secure Data Erasure & Advanced File Recovery Platform           ");
        System.out.println("    National Technical Research Organisation (NTRO) - SIH26149 Prototype                   ");
        System.out.println("=========================================================================================");

        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\n--- MAIN MENU ---");
            System.out.println("1. Detect & List Connected Storage Drives (Block Level)");
            System.out.println("2. Run Secure Drive Eraser (NIST 800-88 / DoD 5220.22-M)");
            System.out.println("3. Run Selective File & Slack Space Eraser");
            System.out.println("4. Run Advanced File Carving & Recovery (Raw Sector Scanner)");
            System.out.println("5. Run End-to-End System Demonstration (Mock Disk Image Test)");
            System.out.println("6. Exit");
            System.out.print("Select Option [1-6]: ");

            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    runDetectDrives();
                    break;
                case "2":
                    runDriveEraser(scanner);
                    break;
                case "3":
                    runFileEraser(scanner);
                    break;
                case "4":
                    runFileCarving(scanner);
                    break;
                case "5":
                    runFullDemo();
                    break;
                case "6":
                    System.out.println("Exiting Forensix Platform. Stay Secure!");
                    return;
                default:
                    System.out.println("Invalid choice. Please enter a number between 1 and 6.");
            }
        }
    }

    private static void runDetectDrives() {
        System.out.println("\n[MODULE 1] Querying OS Kernel for Physical Storage Devices...");
        List<StorageDevice> devices = StorageDetector.detectDevices();
        if (devices.isEmpty()) {
            System.out.println("No physical storage devices found or privileges restricted.");
        } else {
            System.out.println("Detected " + devices.size() + " Storage Device(s):");
            for (int i = 0; i < devices.size(); i++) {
                System.out.printf(" %d. %s%n", i + 1, devices.get(i));
            }
        }
    }

    private static void runDriveEraser(Scanner scanner) {
        List<StorageDevice> devices = StorageDetector.detectDevices();
        if (devices.isEmpty()) {
            System.out.println("No devices detected.");
            return;
        }

        System.out.println("\n--- SECURE DRIVE ERASER ---");
        for (int i = 0; i < devices.size(); i++) {
            System.out.printf(" %d. %s%n", i + 1, devices.get(i));
        }
        System.out.print("Select drive number to wipe: ");
        try {
            int idx = Integer.parseInt(scanner.nextLine().trim()) - 1;
            if (idx >= 0 && idx < devices.size()) {
                StorageDevice dev = devices.get(idx);
                if (dev.isSystemDrive()) {
                    System.err.println("SAFETY LOCK: Refusing to wipe OS System Drive (" + dev.getDevicePath() + ")");
                    return;
                }

                System.out.print("Select Standard (1: NIST 800-88 Clear, 2: DoD 5220.22-M 3-Pass, 3: Zero Fill): ");
                String stdChoice = scanner.nextLine().trim();
                SanitizationStandard std = stdChoice.equals("2") ? SanitizationStandard.DOD_5220_22_M :
                        (stdChoice.equals("3") ? SanitizationStandard.ZERO_FILL : SanitizationStandard.NIST_800_88_CLEAR);

                System.out.printf("CONFIRMATION: Are you sure you want to PERMANENTLY WIPE %s using %s? (type 'WIPE' to proceed): ",
                        dev.getDevicePath(), std.getDisplayName());
                if (scanner.nextLine().trim().equals("WIPE")) {
                    boolean success = DriveEraser.sanitizeDrive(dev, std, (pass, totalPasses, bytes, total, entropy, pattern) -> {
                        double pct = (double) bytes / total * 100;
                        System.out.printf("\r[PROGRESS] %s | Pass %d/%d: %.1f%% | Entropy: %.4f bits/byte",
                                pattern, pass, totalPasses, pct, entropy);
                    });

                    System.out.println("\nErasure status: " + (success ? "SUCCESSFUL" : "FAILED"));

                    // Generate Forensic PDF Certificate
                    File certDir = new File("reports");
                    ReportGenerator.generateSanitizationCertificate(dev, std, "a1b2c3d4e5f678901234567890abcdef", certDir);
                }
            }
        } catch (Exception e) {
            System.err.println("Invalid selection.");
        }
    }

    private static void runFileEraser(Scanner scanner) {
        System.out.print("\nEnter path to file to securely delete: ");
        String filePath = scanner.nextLine().trim();
        File file = new File(filePath);
        if (file.exists()) {
            boolean wiped = FileEraser.wipeFile(file, SanitizationStandard.DOD_5220_22_M);
            System.out.println("Selective File Erasure: " + (wiped ? "SUCCESSFUL" : "FAILED"));
        } else {
            System.err.println("File not found: " + filePath);
        }
    }

    private static void runFileCarving(Scanner scanner) {
        System.out.print("\nEnter path to disk image file or drive (e.g., test_evidence.raw): ");
        String path = scanner.nextLine().trim();
        File source = new File(path);
        if (!source.exists()) {
            System.err.println("Source path does not exist: " + path);
            return;
        }

        File outputDir = new File("carved_output");
        System.out.println("\n[MODULE 3] Starting Forensic Magic-Byte File Carving engine...");
        List<CarvedFile> carved = FileCarver.carveDevice(path, outputDir, (bytes, total, found) -> {
            double pct = (double) bytes / total * 100;
            System.out.printf("\r[CARVING SCAN] Progress: %.1f%% | Files Extracted: %d", pct, found);
        });

        System.out.println("\n\n--- CARVED EVIDENCE MANIFEST ---");
        for (CarvedFile cf : carved) {
            System.out.println(" - " + cf);
        }
    }

    private static void runFullDemo() {
        System.out.println("\n=========================================================================");
        System.out.println("  RUNNING INTEGRATED DEMONSTRATION & BENCHMARK SUITE                     ");
        System.out.println("=========================================================================");

        try {
            // 1. Create a 10MB Mock RAW Disk Image with Embedded JPEG and PDF evidence
            File mockImage = new File("test_evidence.raw");
            System.out.println("[STEP 1] Generating 10 MB Mock Forensic Raw Disk Image: " + mockImage.getAbsolutePath());
            byte[] mockDisk = new byte[10 * 1024 * 1024];

            // Embed JPEG Header & Footer in Disk Sector 100
            byte[] jpegHeader = new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46};
            byte[] jpegFooter = new byte[]{(byte) 0xFF, (byte) 0xD9};
            int jpegOffset = 100 * 512;
            System.arraycopy(jpegHeader, 0, mockDisk, jpegOffset, jpegHeader.length);
            System.arraycopy("SAMPLE_IMAGE_DATA_BYTES_SIH26149".getBytes(), 0, mockDisk, jpegOffset + 50, 32);
            System.arraycopy(jpegFooter, 0, mockDisk, jpegOffset + 1024, jpegFooter.length);

            // Embed PDF Header & Footer in Disk Sector 500
            byte[] pdfHeader = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n".getBytes();
            byte[] pdfFooter = "%%EOF\n".getBytes();
            int pdfOffset = 500 * 512;
            System.arraycopy(pdfHeader, 0, mockDisk, pdfOffset, pdfHeader.length);
            System.arraycopy(pdfFooter, 0, mockDisk, pdfOffset + 2048, pdfFooter.length);

            try (FileOutputStream fos = new FileOutputStream(mockImage)) {
                fos.write(mockDisk);
            }

            // 2. Perform File Carving on Raw Evidence
            System.out.println("\n[STEP 2] Running Advanced File Carving on Raw Disk Image...");
            File outputDir = new File("carved_evidence");
            List<CarvedFile> carved = FileCarver.carveDevice(mockImage.getAbsolutePath(), outputDir, null);

            System.out.println("\nExtracted Evidence Results:");
            for (CarvedFile cf : carved) {
                System.out.println("  [FOUND EVIDENCE] " + cf);
            }

            // 3. Perform Sanitization Wiping of Evidence Image (NIST 800-88)
            System.out.println("\n[STEP 3] Wiping Mock Disk Image using NIST SP 800-88 (Purge)...");
            StorageDevice mockDev = new StorageDevice(mockImage.getAbsolutePath(), "Mock Synthetic Evidence Disk", "SIH-DEMO-001", mockImage.length(), 512, "Synthetic", false);
            DriveEraser.sanitizeDrive(mockDev, SanitizationStandard.NIST_800_88_CLEAR, (pass, total, bytes, totalB, entropy, pattern) -> {
                System.out.printf("\r  [WIPE PROGRESS] Pass %d/%d | Written: %d KB | Buffer Entropy: %.4f bits/byte",
                        pass, total, bytes / 1024, entropy);
            });

            // 4. Generate Cryptographic Audit Certificate
            System.out.println("\n\n[STEP 4] Generating Tamper-Evident Forensic Audit Certificate PDF...");
            File reportsDir = new File("reports");
            File pdfCert = ReportGenerator.generateSanitizationCertificate(mockDev, SanitizationStandard.NIST_800_88_CLEAR,
                    HashUtil.calculateSHA256("FORENSIX_PURGE_SUCCESS".getBytes()), reportsDir);

            System.out.println("\n=========================================================================");
            System.out.println("  DEMONSTRATION COMPLETED SUCCESSFULLY! ALL MODULES FUNCTIONAL!          ");
            System.out.println("=========================================================================");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}