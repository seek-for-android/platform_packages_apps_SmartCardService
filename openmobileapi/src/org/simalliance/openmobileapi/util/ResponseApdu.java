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

package org.simalliance.openmobileapi.util;

import org.simalliance.openmobileapi.internal.ByteArrayConverter;
import org.simalliance.openmobileapi.internal.ErrorStrings;

/**
 * Class that wraps the functionality for dealing with APDU responses.
 */
public final class ResponseApdu {

    /**
     * Override default constructor to prevent instantiation.
     */
    private ResponseApdu() {
    }

    /**
     * Returns the data of a response APDU.
     *
     * @param responseApdu The APDU from which the data is wanted.
     *
     * @return The data of the specified response APDU.
     *
     * @throws IllegalArgumentException if the response does not have SW.
     */
    public static byte[] getResponseData(byte[] responseApdu)
            throws IllegalArgumentException {
        if (responseApdu.length < 2) {
            throw new IllegalArgumentException(ErrorStrings.APDU_BAD_RESPONSE);
        }

        byte[] responseData = new byte[responseApdu.length - 2];
        System.arraycopy(responseApdu, 0, responseData, 0,
                responseApdu.length - 2);
        return responseData;
    }

    /**
     * Returns the SW of a response APDU.
     *
     * @param responseApdu The APDU from which the SW is wanted.
     *
     * @return The SW of the specified response APDU.
     *
     * @throws IllegalArgumentException if the response does not have SW.
     */
    public static byte[] getResponseStatusWordBytes(byte[] responseApdu)
            throws IllegalArgumentException {
        if (responseApdu.length < 2) {
            throw new IllegalArgumentException(ErrorStrings.APDU_BAD_RESPONSE);
        }

        byte[] statusWord = new byte[2];
        System.arraycopy(responseApdu, responseApdu.length - 2, statusWord, 0,
                2);
        return statusWord;
    }

    /**
     * Returns the integer value of the StatusWord of a response APDU.
     *
     * @param responseApdu The APDU from which the SW value is wanted.
     *
     * @return The value of the SW of the specified response APDU.
     *
     * @throws IllegalArgumentException if the response does not have SW.
     */
    public static int getResponseStatusWordValue(byte[] responseApdu)
            throws IllegalArgumentException {
        return ByteArrayConverter.byteArrayToInt(getResponseStatusWordBytes(responseApdu));
    }
}
