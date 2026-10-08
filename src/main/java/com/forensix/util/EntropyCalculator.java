package com.forensix.util;

import java.security.MessageDigest;

public class EntropyCalculator {

    /**
     * Calculates Shannon Entropy of a byte buffer in bits per byte (0.0 to 8.0).
     * 0.0 = Uniform single byte (e.g. all 0x00 zeroes or 0xFF)
     * 8.0 = Completely random data (e.g. encrypted or pseudo-random wipe pass)
     */
    public static double calculateShannonEntropy(byte[] data, int length) {
        if (data == null || length == 0) {
            return 0.0;
        }

        int[] frequency = new int[256];
        for (int i = 0; i < length; i++) {
            frequency[data[i] & 0xFF]++;
        }

        double entropy = 0.0;
        double len = length;

        for (int count : frequency) {
            if (count > 0) {
                double probability = count / len;
                entropy -= probability * (Math.log(probability) / Math.log(2.0));
            }
        }

        return entropy;
    }
}
