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

import org.simalliance.openmobileapi.internal.ErrorStrings;

/**
 * Instances of this class can be used to find a Secure Element implementing a
 * specific Applet, identified by its AID. The presence of such an Applet is
 * verified by trying to open a channel to this Applet. The opened channel, if
 * any, is closed before the end of the isMatching method.
 */
public class SERecognizerByAID extends SERecognizer {

    /**
     * The minimum length of an AID.
     */
    public static final int AID_MIN_LENGTH = 5;

    /**
     * The maximum length of an AID.
     */
    public static final int AID_MAX_LENGTH = 16;

    /**
     * The expected AID.
     */
    private byte[] mAID;

    /**
     * Initializes a new instance of the SERecognizerByAID class.
     *
     * @param aid The expected AID.
     *
     * @throws IllegalArgumentException if the length of AID is not between
     *         AID_MIN_LENGTH and AID_MAX_LENGTH or if it's null.
     */
    public SERecognizerByAID(byte[] aid) throws IllegalArgumentException {

        if (aid == null) {
            throw new IllegalArgumentException(ErrorStrings.paramNull("aid"));
        }
        if ((aid.length < AID_MIN_LENGTH) || (aid.length > AID_MAX_LENGTH)) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidValue("aid"));
        }

        mAID = new byte[aid.length];
        System.arraycopy(aid, 0, mAID, 0, aid.length);
    }

    /**
     * Tries to open a channel with the specified AID.
     *
     * @param session The session in which to open the channel.
     *
     * @return true if the channel could be opened, false otherwise.
     *
     * @throws IllegalArgumentException if the used session is null.
     */
    public boolean isMatching(Session session) throws IllegalArgumentException {
        if (session == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("session"));
        }
        try {
            Channel channel = session.openLogicalChannel(mAID);
            if (channel != null) {
                channel.close();
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }
}
