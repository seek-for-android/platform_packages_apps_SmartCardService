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

import java.io.IOException;

import org.simalliance.openmobileapi.Channel;
import org.simalliance.openmobileapi.internal.ErrorStrings;

/**
 * Class that wraps the functionality for forming and sending APDUs.
 */
public class CommandApdu {

    /**
     * CLA values.
     */

    /**
     * Interindustry class value.
     */
    public static final byte CLA_INTERINDUSTRY  = (byte) 0x00;
    /**
     * Proprietary class value.
     */
    public static final byte CLA_PROPRIETARY    = (byte) 0x80;

    /**
     * ISO instruction values.
     */

    /**
     * ISO APPEND RECORD instruction value.
     */
    public static final byte INS_APPEND_RECORD      = (byte) 0xE2;
    /**
     * ISO CHANGE REFERENCE DATA instruction value.
     */
    public static final byte INS_CHANGE_REF_DATA    = (byte) 0x24;
    /**
     * ISO ENABLE VERIFICAITION REQUIREMENT instruction value.
     */
    public static final byte INS_ENABLE_VERIF_REQ   = (byte) 0x28;
    /**
     * ISO DISABLE VERIFICATION REQUIREMENT instruction value.
     */
    public static final byte INS_DISABLE_VERIF_REQ  = (byte) 0x26;
    /**
     * ISO READ BINARY instruction value (0xB0).
     */
    public static final byte INS_READ_BINARY_B0     = (byte) 0xB0;
    /**
     * ISO READ BINARY instruction value (0xB1).
     */
    public static final byte INS_READ_BINARY_B1     = (byte) 0xB1;
    /**
     * ISO READ RECORD instruction value (0xB2).
     */
    public static final byte INS_READ_RECORD_B2     = (byte) 0xB2;
    /**
     * ISO READ RECORD instruction value (0xB3).
     */
    public static final byte INS_READ_RECORD_B3     = (byte) 0xB3;
    /**
     * ISO RESET RETRY COUNTER instruction value.
     */
    public static final byte INS_RESET_RETRY_CTR    = (byte) 0x2C;
    /**
     * ISO SEARCH RECORD instruction value.
     */
    public static final byte INS_SEARCH_RECORD      = (byte) 0xA2;
    /**
     * ISO SELECT instruction value.
     */
    public static final byte INS_SELECT             = (byte) 0xA4;
    /**
     * ISO UPDATE BINARY instruction value (0xD6).
     */
    public static final byte INS_UPDATE_BINARY_D6   = (byte) 0xD6;
    /**
     * ISO UPDATE RECORD instruction value (0xDC).
     */
    public static final byte INS_UPDATE_RECORD_DC   = (byte) 0xDC;
    /**
     * ISO VERIFY instruction value (0x20).
     */
    public static final byte INS_VERIFY_20          = (byte) 0x20;
    /**
     * ISO VERIFY instruction value (0x21).
     */
    public static final byte INS_VERIFY_21          = (byte) 0x21;
    /**
     * ISO WRITE BINARY instruction value (0xD0).
     */
    public static final byte INS_WRITE_BINARY_D0    = (byte) 0xD0;
    /**
     * ISO WRITE BINARY instruction value (0xD1).
     */
    public static final byte INS_WRITE_BINARY_D1    = (byte) 0xD1;
    /**
     * ISO WRITE RECORD instruction value.
     */
    public static final byte INS_WRITE_RECORD       = (byte) 0xD2;

    /**
     * Secure Storage INS values.
     */

    /**
     * SIM Alliance Secure Storage Applet instruction values.
     */

    /**
     * SIM Alliance Secure Storage PING SS APPLET instruction value.
     */
    public static final byte INS_PING_SS_APPLET = (byte) 0xAA;
    /**
     * SIM Alliance Secure Storage CREATE SS ENTRY instruction value.
     */
    public static final byte INS_CREATE_SS_ENTRY = (byte) 0xE0;
    /**
     * SIM Alliance Secure Storage DELETE ALL SS ENTRIES instruction value.
     */
    public static final byte INS_DELETE_ALL_SS_ENTRIES = (byte) 0xE5;
    /**
     * SIM Alliance Secure Storage DELETE SS ENTRY instruction value.
     */
    public static final byte INS_DELETE_SS_ENTRY = (byte) 0xE4;
    /**
     * SIM Alliance Secure Storage GET SS ENTRY DATA instruction value.
     */
    public static final byte INS_GET_SS_ENTRY_DATA = (byte) 0xCA;
    /**
     * SIM Alliance Secure Storage GET SS ENTRY ID instruction value.
     */
    public static final byte INS_GET_SS_ENTRY_ID = (byte) 0xB2;
    /**
     * SIM Alliance Secure Storage SELECT SS ENTRY instruction value.
     */
    public static final byte INS_SELECT_SS_ENTRY = (byte) 0xA5;
    /**
     * SIM Alliance Secure Storage PUT SS ENTRY DATA instruction value.
     */
    public static final byte INS_PUT_SS_ENTRY_DATA = (byte) 0xDA;

    /**
     * The maximum value of the data field of an APDU.
     * TODO: Extended data length APDUs not supported.
     */
    public static final int MAX_DATA_LENGTH = 255;

    /**
     * The channel over which the APDU will be sent.
     */
    private Channel mChannel;

    /**
     * The value of the CLA field.
     */
    private byte mCla;

    /**
     * The value of the INS field.
     */
    private byte mIns;

    /**
     * The value of the P1 field.
     */
    private byte mP1;

    /**
     * The value of the P2 field.
     */
    private byte mP2;
    /**
     * The value of the Data field.
     */
    private byte[] mData;
    /**
     * The value of the Le field.
     */
    private int mLe;

    /**
     * Indicate presence of CLA field in the APDU.
     */
    private boolean isClaPresent;

    /**
     * Indicate presence of INS field in the APDU.
     */
    private boolean isInsPresent;

    /**
     * Indicate presence of P1 field in the APDU.
     */
    private boolean isP1Present;

    /**
     * Indicate presence of P2 field in the APDU.
     */
    private boolean isP2Present;

    /**
     * Indicate presence of Data field in the APDU.
     */
    private boolean isDataPresent;

    /**
     * Indicate presence of Le field in the APDU.
     */
    private boolean isLePresent;

    /**
     * Initializes a new instance of the class.
     *
     * @param channel The Channel to be used.
     */
    public CommandApdu(Channel channel) {
        mChannel = channel;
        isClaPresent = false;
        isInsPresent = false;
        isP1Present = false;
        isP2Present = false;
        isDataPresent = false;
        isLePresent = false;
    }

    /**
     * Decides whether present fields will form a valid APDU.
     *
     * @return true if an APDU can be formed, false otherwise.
     */
    private boolean canApduBeFormed() {
        return isClaPresent && isInsPresent && isP1Present && isP2Present;
    }

    /**
     * Forms a byte array that represents an APDU with the already set fields in
     * the class.
     *
     * @return A byte array representing an APDU with the fields of this APDU
     *         instance. null if the field combination is invalid.
     *
     * @throws IllegalArgumentException if the APDU has an invalid format.
     */
    public byte[] formApdu() throws IllegalArgumentException {
        if (canApduBeFormed()) {
            byte[] apdu;
            if (!isDataPresent && !isLePresent) {
                apdu = new byte[4];
                apdu[0] = mCla;
                apdu[1] = mIns;
                apdu[2] = mP1;
                apdu[3] = mP2;
            } else if (!isDataPresent && isLePresent) {
                apdu = new byte[5];
                apdu[0] = mCla;
                apdu[1] = mIns;
                apdu[2] = mP1;
                apdu[3] = mP2;
                apdu[4] = (byte) mLe;
            } else if (isDataPresent && !isLePresent) {
                apdu = new byte[5 + mData.length];
                apdu[0] = mCla;
                apdu[1] = mIns;
                apdu[2] = mP1;
                apdu[3] = mP2;
                apdu[4] = (byte) mData.length;
                System.arraycopy(mData, 0, apdu, 5, mData.length);
            } else {
                apdu = new byte[6 + mData.length];
                apdu[0] = mCla;
                apdu[1] = mIns;
                apdu[2] = mP1;
                apdu[3] = mP2;
                apdu[4] = (byte) mData.length;
                System.arraycopy(mData, 0, apdu, 5, mData.length);
                apdu[apdu.length - 1] = (byte) mLe;
            }

            return apdu;
        } else {
            throw new IllegalArgumentException("Invalid APDU format.");
        }
    }

    /**
     * Sets the CLA field.
     *
     * @param cla The value to be set.
     */
    public void setCla(byte cla) {
        mCla = cla;
        isClaPresent = true;
    }

    /**
     * Sets the INS field.
     *
     * @param ins The value to be set.
     */
    public void setIns(byte ins) {
        mIns = ins;
        isInsPresent = true;
    }

    /**
     * Sets the P1 field.
     *
     * @param p1 The value to be set.
     */
    public void setP1(byte p1) {
        mP1 = p1;
        isP1Present = true;
    }

    /**
     * Sets the P2 field.
     *
     * @param p2 The value to be set.
     */
    public void setP2(byte p2) {
        mP2 = p2;
        isP2Present = true;
    }

    /**
     * Sets the Data field.
     *
     * @param data The value to be set. Lc is automatically generated
     *
     * @throws IllegalArgumentException if the data length is invalid or data is
     *         null.
     */
    public void setData(byte[] data) throws IllegalArgumentException {
        if (data == null) {
            throw new IllegalArgumentException(ErrorStrings.paramNull("data"));
        }
        if (data.length > MAX_DATA_LENGTH) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("data"));
        }

        mData = data;
        isDataPresent = true;
    }

    /**
     * Sets the Le field.
     *
     * @param le The value to be set.
     *
     * @throws IllegalArgumentException if the Le value is invalid.
     */
    public void setLE(int le) throws IllegalArgumentException {
        if ((le > CommandApdu.MAX_DATA_LENGTH) || (le < 0)) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidValue("le"));
        }

        mLe = le;
        isLePresent = true;
    }

    /**
     * Sends the APDU over the specified channel.
     *
     * @return The SmartCard response.
     *
     * @throws IllegalStateException if the channel is closed.
     * @throws IllegalArgumentException if the APDU has an invalid format.
     * @throws IOException Lower-level API exception.
     */
    public byte[] sendApdu() throws IllegalStateException, IOException,
            IllegalArgumentException {

        if (mChannel.isClosed()) {
            throw new IllegalStateException(ErrorStrings.CHANNEL_CLOSED);
        } else {
            return mChannel.transmit(formApdu());
        }
    }
}
