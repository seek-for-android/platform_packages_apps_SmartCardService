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

/**
 * Instances of this class can be used to find a Secure Element with a specific
 * ATR (or ATR pattern).
 */
public class SERecognizerByATR extends SERecognizer {

    /**
     * The minimum length of an ATR (At least TS and t0 shall be present.
     */
    public static final int ATR_MIN_LENGTH = 2;

    /**
     * The maximum length of an ATR.
     */
    public static final int ATR_MAX_LENGTH = 32;

    /**
     * The ATR to look for.
     */
    private byte[] mAtr;

    /**
     * The mask that will be applied to the SE ATR.
     */
    private byte[] mMask;

    /**
     * Initializes a new instance of the SERecognizerByATR class.
     *
     * @param atr A byte array containing the ATR bytes values that are searched
     *        for.
     * @param mask A byte array containing an AND-mask to be applied to the
     *        Secure Element ATR values before to be compared with the searched
     *        value.
     *
     * @throws IllegalArgumentException when either the ATR or the Mask parameters
     *         have an invalid length, or if they are null.
     */
    public SERecognizerByATR(byte[] atr, byte[] mask)
            throws IllegalArgumentException {
        if (atr == null) {
            throw new IllegalArgumentException(ErrorStrings.paramNull("atr"));
        }
        if (mask == null) {
            throw new IllegalArgumentException(ErrorStrings.paramNull("mask"));
        }

        if (atr.length < ATR_MIN_LENGTH || atr.length > ATR_MAX_LENGTH) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("atr"));
        }

        if (atr.length != mask.length) {
            throw new IllegalArgumentException(
                    "atr length and mask length must be equal.");
        }

        mAtr = new byte[atr.length];
        System.arraycopy(atr, 0, mAtr, 0, atr.length);
        mMask = new byte[mask.length];
        System.arraycopy(mask, 0, mMask, 0, mask.length);
    }

    /**
     * If the ATR length is correct, masks it and compares it with the expected
     * one.
     *
     * @param session The session from which the ATR will be get.
     *
     * @return true if the masked ATRs match, or false if either ATRs don't
     *         match or session ATR has an invalid length.
     *
     * @throws IllegalArgumentException if session is null.
     */
    public boolean isMatching(Session session) throws IllegalArgumentException {
        if (session == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("session"));
        }
        byte[] sessionAtr = session.getATR();

        if (sessionAtr.length != mAtr.length) {
            return false;
        }

        return Arrays.equals(maskAtr(mAtr, mMask), maskAtr(sessionAtr, mMask));
    }

    /**
     * Masks the specified ATR with the specified mask.
     *
     * @param atr The ATR to be masked.
     * @param mask The mask to be applied to the ATR.
     *
     * @return The masked ATR.
     */
    private byte[] maskAtr(byte[] atr, byte[] mask) {
        byte[] maskedAtr = new byte[atr.length];

        for (int i = 0; i < atr.length; i++) {
            maskedAtr[i] = (byte) (atr[i] & mask[i]);
        }

        return maskedAtr;
    }
}
