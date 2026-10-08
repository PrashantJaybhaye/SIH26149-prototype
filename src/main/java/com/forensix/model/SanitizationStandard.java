package com.forensix.model;

public enum SanitizationStandard {
    NIST_800_88_CLEAR("NIST SP 800-88 Rev 1 (Clear)", 1, "Single-pass logical zero overwrite for non-classified data destruction."),
    NIST_800_88_PURGE("NIST SP 800-88 Rev 1 (Purge)", 3, "Cryptographic or physical 3-pass overwrite executing hardware purge commands."),
    DOD_5220_22_M("DoD 5220.22-M (3-Pass)", 3, "Pass 1: 0x00, Pass 2: 0xFF, Pass 3: Random byte pattern with hash verification."),
    GUTMANN_LITE("Gutmann (Lite 7-Pass)", 7, "7-pass pseudo-random complex magnetic field polarization overwrite."),
    ZERO_FILL("Single Pass Zero (Fast)", 1, "High-speed single pass zero-fill (0x00)."),
    RANDOM_FILL("Single Pass Pseudo-Random", 1, "High-speed single pass cryptographically secure random byte fill.");

    private final String displayName;
    private final int totalPasses;
    private final String description;

    SanitizationStandard(String displayName, int totalPasses, String description) {
        this.displayName = displayName;
        this.totalPasses = totalPasses;
        this.description = description;
    }

    public String getDisplayName() { return displayName; }
    public int getTotalPasses() { return totalPasses; }
    public String getDescription() { return description; }

    @Override
    public String toString() {
        return displayName + " (" + totalPasses + " passes)";
    }
}
