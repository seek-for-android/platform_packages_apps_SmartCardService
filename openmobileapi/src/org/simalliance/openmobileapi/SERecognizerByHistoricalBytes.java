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

package org.simalliance.openmobileapi;

import java.util.Arrays;

import org.simalliance.openmobileapi.internal.ErrorStrings;
import org.simalliance.openmobileapi.internal.HistoricalBytesUtilities;

/**
 * Instances of this class can be used to find a Secure Element with a specific
 * value in their historical bytes.
 */
public class SERecognizerByHistoricalBytes extends SERecognizer {

    /**
     * The minimum length of the historical bytes.
     */
    public static final int HISTORICAL_BYTES_MIN_LENGTH = 0;

    /**
     * The maximum length of the historical bytes.
     */
    public static final int HISTORICAL_BYTES_MAX_LENGTH = 15;

    /**
     * The expected historical bytes.
     */
    private byte[] mHistBytes;

    /**
     * Initializes a new instance of the SERecognizerByHistoricalBytes class.
     *
     * @param values Byte array, to be checked for presence in the historical
     *        bytes.
     *
     * @throws IllegalArgumentException if values has a wrong length or it's null.
     */
    public SERecognizerByHistoricalBytes(byte[] values)
            throws IllegalArgumentException {
        if (values == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("values"));
        }
        if (values.length < HISTORICAL_BYTES_MIN_LENGTH
                || values.length > HISTORICAL_BYTES_MAX_LENGTH) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("values"));
        }

        mHistBytes = new byte[values.length];
        System.arraycopy(values, 0, mHistBytes, 0, values.length);
    }

    /**
     * Gets the historical bytes and compares them with the expected ones.
     *
     * @param session The session from which the historical bytes will be get.
     *
     * @return true if the historical bytes match, or false if either historical
     *         bytes don't match or session ATR has an invalid length.
     *
     * @throws IllegalArgumentException if the used session is null.
     */
    public boolean isMatching(Session session) throws IllegalArgumentException {
        if (session == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("session"));
        }
        byte[] sessionHistBytes = HistoricalBytesUtilities.getHistBytes(session
                .getATR());
        return Arrays.equals(mHistBytes, sessionHistBytes);
    }
}
