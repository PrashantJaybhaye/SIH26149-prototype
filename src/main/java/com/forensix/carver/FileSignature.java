package com.forensix.carver;

import java.util.ArrayList;
import java.util.List;

public class FileSignature {
    private final String name;
    private final String extension;
    private final byte[] headerMagic;
    private final byte[] footerMagic;
    private final long maxSizeBytes;

    public FileSignature(String name, String extension, byte[] headerMagic, byte[] footerMagic, long maxSizeBytes) {
        this.name = name;
        this.extension = extension;
        this.headerMagic = headerMagic;
        this.footerMagic = footerMagic;
        this.maxSizeBytes = maxSizeBytes;
    }

    public String getName() { return name; }
    public String getExtension() { return extension; }
    public byte[] getHeaderMagic() { return headerMagic; }
    public byte[] getFooterMagic() { return footerMagic; }
    public long getMaxSizeBytes() { return maxSizeBytes; }

    public static List<FileSignature> getStandardForensicSignatures() {
        List<FileSignature> signatures = new ArrayList<>();

        // JPEG (SOI: FF D8 FF E0 or FF D8 FF E1 | EOI: FF D9)
        signatures.add(new FileSignature(
                "JPEG Image", ".jpg",
                new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF},
                new byte[]{(byte) 0xFF, (byte) 0xD9},
                20 * 1024 * 1024 // 20 MB max
        ));

        // PNG (Header: 89 50 4E 47 0D 0A 1A 0A | Footer: IEND 49 45 4E 44 AE 42 60 82)
        signatures.add(new FileSignature(
                "PNG Image", ".png",
                new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
                new byte[]{0x49, 0x45, 0x4E, 0x44, (byte) 0xAE, 0x42, 0x60, (byte) 0x82},
                30 * 1024 * 1024 // 30 MB max
        ));

        // PDF Document (Header: %PDF- | Footer: %%EOF)
        signatures.add(new FileSignature(
                "PDF Document", ".pdf",
                new byte[]{0x25, 0x50, 0x44, 0x46, 0x2D}, // %PDF-
                new byte[]{0x25, 0x25, 0x45, 0x4F, 0x46}, // %%EOF
                50 * 1024 * 1024 // 50 MB max
        ));

        // ZIP Archive / DOCX / XLSX (Header: PK\x03\x04 | Footer: PK\x05\x06)
        signatures.add(new FileSignature(
                "ZIP/Office Document", ".zip",
                new byte[]{0x50, 0x4B, 0x03, 0x04},
                new byte[]{0x50, 0x4B, 0x05, 0x06},
                100 * 1024 * 1024 // 100 MB max
        ));

        return signatures;
    }
}
