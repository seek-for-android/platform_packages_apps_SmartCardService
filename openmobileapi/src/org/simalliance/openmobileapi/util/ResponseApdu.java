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

    // 9000 - Normal processing - No further qualification.
    /**
     * No further qualification.
     */
    public static final int SW_NO_FURTHER_QUALIFICATION = 0x9000;

    // 61XX - Normal processing - SW2 encodes the number of data bytes still
    // available.
    /**
     * SW2 encodes the number of data bytes still available (minimum value).
     */
    public static final int SW_NORMAL_PROCESSING_MIN = 0x6100;
    /**
     * SW2 encodes the number of data bytes still available (maximum value).
     */
    public static final int SW_NORMAL_PROCESSING_MAX = 0x61FF;

    // 62XX - Warning processing - State of non-volatile memory is unchanged
    // (further qualification in SW2).
    /**
     * No information given.
     */
    public static final int SW_62_NO_INFO = 0x6200;
    /**
     * Triggering by the card (minimum value).
     */
    public static final int SW_62_TRIGGERING_CARD_MIN = 0x6202;
    /**
     * Triggering by the card (maximum value).
     */
    public static final int SW_62_TRIGGERING_CARD_MAX = 0x6280;
    /**
     * Part of returned data may be corrupted.
     */
    public static final int SW_DATA_CORRUPTED = 0x6281;
    /**
     * End of file or record reached before reading Ne bytes.
     */
    public static final int SW_UNEXPECTED_EOF = 0x6282;
    /**
     * Selected file deactivated.
     */
    public static final int SW_FILE_DEACTIVATED = 0x6283;
    /**
     * File control information not formatted according to 5.3.3.
     */
    public static final int SW_WRONG_FILE_CONTROL_FORMAT = 0x6284;
    /**
     * Selected file in termination state.
     */
    public static final int SW_FILE_STATE_TERMINATION = 0x6285;
    /**
     * No input data available from a sensor on the card.
     */
    public static final int SW_NO_INPUT_DATA_AVAILABLE = 0x6286;

    // 63XX - Warning processing - State of non-volatile memory has
    // changed (further qualification in SW2).
    /**
     * No information given.
     */
    public static final int SW_63_NO_INFO = 0x6300;
    /**
     * File filled up by the last write.
     */
    public static final int SW_FILE_FILLED_UP = 0x6381;
    /**
     * Counter from 0 to 15 encoded by X (exact meaning depending on the
     * command). Minimum value.
     */
    public static final int SW_CTR_MIN = 0x63C0;
    /**
     * Counter from 0 to 15 encoded by X (exact meaning depending on the
     * command). Maximum value.
     */
    public static final int SW_CTR_MAX = 0x63CF;

    // 64XX - Execution error - State of non-volatile memory is
    // unchanged (further qualification in SW2)
    /**
     * Execution error.
     */
    public static final int SW_EXEC_ERROR = 0x6400;
    /**
     * Immediate response required by the card.
     */
    public static final int SW_IMMEDIATE_RESPONSE_REQUIRED = 0x6401;
    /**
     * Triggering by the card (minimum value).
     */
    public static final int SW_64_TRIGGERING_CARD_MIN = 0x6402;
    /**
     * Triggering by the card (maximum value).
     */
    public static final int SW_64_TRIGGERING_CARD_MAX = 0x6480;

    // 65XX - Execution error - State of non-volatile memory has changed
    // (further qualification in SW2)
    /**
     * No information given.
     */
    public static final int SW_65_NO_INFO = 0x6500;
    /**
     * Memory failure.
     */
    public static final int SW_MEMORY_FAILURE = 0x6581;

    // 66XX - Execution error - Security-related issues
    /**
     * Security issue (minimum value).
     */
    public static final int SW_SECURITY_ISSUE_MIN = 0x6600;
    /**
     * Security issue (maximum value).
     */
    public static final int SW_SECURITY_ISSUE_MAX = 0x66FF;

    // 6700 - Checking error - Wrong length, no further indication
    /**
     * Wrong length, no further indication.
     */
    public static final int SW_WRONG_LENGTH = 0x6700;

    // 68XX - Checking error - Functions in CLA not supported
    // (further qualification in SW2)
    /**
     * No information given.
     */
    public static final int SW_68_NO_INFO = 0x6800;
    /**
     * Logical channel not supported.
     */
    public static final int SW_LOGICAL_CHANNEL_NOT_SUPPORTED = 0x6881;
    /**
     * Secure messaging not supported.
     */
    public static final int SW_SECURE_MESSAGING_NOT_SUPPORTED = 0x6882;
    /**
     * Last command of the chain expected.
     */
    public static final int SW_LAST_COMMAND_EXPECTED = 0x6883;
    /**
     * Command chaining not supported.
     */
    public static final int SW_COMMAND_CHAINING_NOT_SUPPORTED = 0x6884;

    // 69XX - Checking error - Command not allowed (further
    // qualification in SW2).
    /**
     * No information given.
     */
    public static final int SW_69_NO_INFO = 0x6900;
    /**
     * Command incompatible with file structure.
     */
    public static final int SW_COMMAND_INCOMPATIBLE = 0x6981;
    /**
     * Security status not satisfied.
     */
    public static final int SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;
    /**
     * Authentication method blocked.
     */
    public static final int SW_AUTH_METHOD_BLOCKED = 0x6983;
    /**
     * Reference data not usable.
     */
    public static final int SW_REF_DATA_NOT_USABLE = 0x6984;
    /**
     * Conditions of use not satisfied.
     */
    public static final int SW_CONDITIONS_NOT_SATISFIED = 0x6985;
    /**
     * Command not allowed (no current EF).
     */
    public static final int SW_COMMAND_NOT_ALLOWED = 0x6986;
    /**
     * Expected secure messaging data objects missing.
     */
    public static final int SW_SM_OBJECT_MISSING = 0x6987;
    /**
     * Incorrect secure messaging data objects.
     */
    public static final int SW_SM_INCORRECT_OBJECT = 0x6988;

    // 6AXX - Checking error - Wrong parameters P1-P2 (further
    // qualification in SW2)
    /**
     * No information given.
     */
    public static final int SW_6A_NO_INFO = 0x6A00;
    /**
     * Incorrect parameters in the command data field.
     */
    public static final int SW_WRONG_DATA = 0x6A80;
    /**
     * Function not supported.
     */
    public static final int SW_FUNC_NOT_SUPPORTED = 0x6A81;
    /**
     * File or application not found.
     */
    public static final int SW_FILE_OR_APP_NOT_FOUND = 0x6A82;
    /**
     * Record not found.
     */
    public static final int SW_RECORD_NOT_FOUND = 0x6A83;
    /**
     * Not enough memory space in the file.
     */
    public static final int SW_NOT_ENOUGH_MEMORY = 0x6A84;
    /**
     * Nc inconsistent with TLV structure.
     */
    public static final int SW_WRONG_NC_TLV = 0x6A85;
    /**
     * Incorrect parameters P1-P2.
     */
    public static final int SW_INCORRECT_P1P2 = 0x6A86;
    /**
     * Nc inconsistent with parameters P1-P2.
     */
    public static final int SW_WRONG_NC_P1P2 = 0x6A87;
    /**
     * Referenced data or reference data not found (exact meaning depending on
     * the command).
     */
    public static final int SW_REF_NOT_FOUND = 0x6A88;
    /**
     * File already exists.
     */
    public static final int SW_FILE_ALREADY_EXISTS = 0x6A89;
    /**
     * DF name already exists.
     */
    public static final int SW_DF_NAME_ALREADY_EXISTS = 0x6A8A;

    // 6B00 - Checking error - Wrong parameters P1-P2
    /**
     * Wrong parameters P1-P2.
     */
    public static final int SW_WRONG_PARAMETERS_P1P2 = 0x6B00;

    // 6CXX - Checking error - Wrong Le field; SW2 encodes the exact
    // number of available data bytes.
    /**
     * Wrong Le field; SW2 encodes the exact number of available data bytes
     * (minimum value).
     */
    public static final int SW_WRONG_LE_MIN = 0x6C00;
    /**
     * Wrong Le field; SW2 encodes the exact number of available data bytes
     * (maximum value).
     */
    public static final int SW_WRONG_LE_MAX = 0x6CFF;

    // 6D00 - Checking error - Instruction code not supported or
    // invalid.
    /**
     * Instruction code not supported or invalid.
     */
    public static final int SW_INS_NOT_SUPPORTED = 0x6D00;

    // 6E00 - Checking error - Class not supported.
    /**
     * Class not supported.
     */
    public static final int SW_CLA_NOT_SUPPORTED = 0x6E00;

    // 6F00 - Checking error - No precise diagnostic
    /**
     * No precise diagnostic.
     */
    public static final int SW_NO_PRECISE_DIAGNOSTIC = 0x6F00;

    /**
     * SW for Secure Storage.
     */

    /**
     * Incorrect values in the command data (if the defined title
     *  does not exist).
     */
    public static final int SES_SW_INCORRECT_COMMAND_DATA = 0x6A80;

    /**
     * Security status not satisfied (if PIN verified state is not set).
     */
    public static final int SES_SW_SECURITY_STATUS_NOT_SATISFIED = 0x6A82;

    /**
     * Invalid instruction.
     */
    public static final int SES_SW_INVALID_INSTRUCTION = 0x6D00;

    /**
     * Memory failure (if the creation of the entry fails due to memory issues).
     */
    public static final int SES_SW_MEMORY_FAILURE = 0x6581;

    /**
     * Not enough memory space (if not enough memory resources are available).
     */
    public static final int SES_SW_NOT_ENOUGH_MEMORY = 0x6A84;
    /**
     * Referenced data not found (if no SeS entry is currently selected).
     */
    public static final int SES_SW_REF_NOT_FOUND = 0x6A88;

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
