package com.forensix.model;

public class CarvedFile {
    private final String id;
    private final String fileType;        // e.g., "JPEG", "PDF", "PNG", "ZIP"
    private final String extension;       // e.g., ".jpg", ".pdf"
    private final long startLba;          // Logical Block Address where header was found
    private final long startByteOffset;   // Absolute byte offset on disk/image
    private final long lengthBytes;       // Extracted length in bytes
    private final double confidenceScore; // 0.0 to 1.0 (e.g. 0.95 = 95%)
    private final String sha256Hash;      // Forensic hash of carved file
    private final boolean isIntact;       // Has valid header + footer matching
    private String outputFilePath;       // Where carved file is stored

    public CarvedFile(String id, String fileType, String extension, long startLba, long startByteOffset,
                      long lengthBytes, double confidenceScore, String sha256Hash, boolean isIntact) {
        this.id = id;
        this.fileType = fileType;
        this.extension = extension;
        this.startLba = startLba;
        this.startByteOffset = startByteOffset;
        this.lengthBytes = lengthBytes;
        this.confidenceScore = confidenceScore;
        this.sha256Hash = sha256Hash;
        this.isIntact = isIntact;
    }

    public String getId() { return id; }
    public String getFileType() { return fileType; }
    public String getExtension() { return extension; }
    public long getStartLba() { return startLba; }
    public long getStartByteOffset() { return startByteOffset; }
    public long getLengthBytes() { return lengthBytes; }
    public double getConfidenceScore() { return confidenceScore; }
    public String getSha256Hash() { return sha256Hash; }
    public boolean isIntact() { return isIntact; }
    
    public String getOutputFilePath() { return outputFilePath; }
    public void setOutputFilePath(String outputFilePath) { this.outputFilePath = outputFilePath; }

    public String getFormattedSize() {
        if (lengthBytes >= 1024 * 1024) {
            return String.format("%.2f MB", lengthBytes / (1024.0 * 1024.0));
        } else if (lengthBytes >= 1024) {
            return String.format("%.2f KB", lengthBytes / 1024.0);
        }
        return lengthBytes + " Bytes";
    }

    @Override
    public String toString() {
        return String.format("[%s] %s (%s) @ LBA %d | Size: %s | Score: %.1f%% | Hash: %s",
                id, fileType, extension, startLba, getFormattedSize(), confidenceScore * 100,
                sha256Hash != null ? sha256Hash.substring(0, Math.min(12, sha256Hash.length())) + "..." : "N/A");
    }
}
