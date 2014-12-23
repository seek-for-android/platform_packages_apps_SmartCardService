/*
 * Copyright 2013 Giesecke & Devrient GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.simalliance.openmobileapi.internal;

/**
 * Utilities class.
 *
 */
public final class ByteArrayConverter {

    /**
     * Override the default constructor to make it private.
     */
    private ByteArrayConverter() {
    }

    /**
     * Indicate the length of a short.
     */
    public static final int SHORT_SIZE = 2;

    /**
     * Indicate the beginning of the Array.
     */
    public static final int BEGINNING_ARRAY = 0;

    /**
     * Forms a char string from the byte array. Mostly used to convert
     *  ASCII characters.
     *
     * @param byteArray The byte array to be hex-encoded.
     *
     * @return the char string.
     */
    public static String byteArrayToCharString(byte[] byteArray) {
        if (byteArray == null) {
            return "";
        }

        StringBuffer sb = new StringBuffer();

        for (byte b : byteArray) {
            sb.append((char) b);
        }

        return sb.toString();
    }

    /**
     * Forms a FileViewProvider-compatible path String (i.e., transforms the
     * byte array {0x3F, 0x00, 0x2F, 0xE2} into the String "3F00:2FE2").
     *
     * @param rawPath The byte array containing the path component.
     *
     * @return A FileViewProvider-compatible path String.
     *
     * @throws IllegalArgumentException if the path has a bad coding.
     */
    public static String byteArrayToPathString(byte[] rawPath)
            throws IllegalArgumentException {
        if (rawPath.length % 2 != 0) {
            throw new IllegalArgumentException("Invald path");
        }

        byte[] buffer = new byte[2];
        String path = "";
        for (int i = 0; i < rawPath.length; i += 2) {
            System.arraycopy(rawPath, i, buffer, 0, 2);
            path = path.concat(byteArrayToHexString(buffer));
            if (i != rawPath.length - 2) {
                path = path.concat(":");
            }
        }
        return path;
    }


    /**
     * Forms an hex-encoded String of the specified byte array.
     *
     * @param byteArray The byte array to be hex-encoded.
     *
     * @return An hex-encoded String of the specified byte array.
     */
    public static String byteArrayToHexString(byte[] byteArray) {
        if (byteArray == null) {
            return "";
        }

        StringBuffer sb = new StringBuffer();

        for (byte b : byteArray) {
            sb.append(String.format("%02x", b & 0xFF));
        }

        return sb.toString();
    }

    /**
     * Forms a byte array containing the values of the hex-encoded string.
     *
     * @param str The hex-encoded string to be converted to byte-array.
     *
     * @return A byte array containing the values of the hex-encoded string.
     */
    public static byte[] hexStringToByteArray(String str) {
        if (str.length() % 2 != 0) {
            return null;
        }

        str = str.toUpperCase();

        byte[] outputBytes = new byte[str.length() / 2];

        for (int i = 0; i < str.length(); i += 2) {

            if (!isHexChar(str.charAt(i)) || !isHexChar(str.charAt(i + 1))) {
                // Return null if invalid characters
                return null;
            }

            outputBytes[i / 2] = (byte) (
                    (Character.digit(str.charAt(i), 16) << 4)
                    + Character.digit(str.charAt(i + 1), 16));
        }

        return outputBytes;
    }

    /**
     * Forms a byte array containing the specified integer value.
     *
     * @param value The integer value to be converted to byte array.
     *
     * @return A byte array containing the specified integer value.
     */
    public static byte[] intToByteArray(int value) {
        return new byte[] {
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value};
    }

    /**
     * Forms an integer from a byte array.
     *
     * @param byteArray The byte array from where to form the integer.
     *
     * @return The integer value representing the specified byte array. 0 if the
     *         array is empty. If the array is longer than 4 bytes, only bytes 0
     *         to 3 will be considered.
     */
    public static int byteArrayToInt(byte[] byteArray) {
        switch (byteArray.length) {
        case 0:
            return 0;
        case 1:
            return (byteArray[0] & 0xFF);
        case 2:
            return (byteArray[0] & 0xFF) << 8 | (byteArray[1] & 0xFF);
        case 3:
            return (byteArray[0] & 0xFF) << 16 | (byteArray[1] & 0xFF) << 8
                    | (byteArray[2] & 0xFF);
        default:
            return (byteArray[0] & 0xFF) << 24 | (byteArray[1] & 0xFF) << 16
                    | (byteArray[2] & 0xFF) << 8 | byteArray[3] & 0xFF;

        }
    }

    /**
     * Decides whether a char is a valid hex value or not.
     *
     * @param c The char to be evaluated.
     *
     * @return true if the specified char is a valid hex value, false otherwise.
     */
    public static boolean isHexChar(char c) {
        if (Character.isLowerCase(c)) {
            c = Character.toUpperCase(c);
        }

        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
    }
}
