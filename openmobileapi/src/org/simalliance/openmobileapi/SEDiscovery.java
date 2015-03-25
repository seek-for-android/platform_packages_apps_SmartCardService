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

import java.io.IOException;

import org.simalliance.openmobileapi.internal.ErrorStrings;

/**
 * Instances of this class must be created by the applications to start a
 * discovery process. When created, they are configured with an SEService and an
 * object that will perform the discovery algorithm.
 */
public class SEDiscovery {

    /**
     * The SEService in which to perform the recognition algorithm.
     */
    private SEService mService;

    /**
     * The Secure Element recognizer.
     */
    private SERecognizer mRecognizer;

    /**
     * The list of available readers in the SEService.
     */
    private Reader[] mReaders;

    /**
     * A counter specifying the last reader returned.
     */
    private int mCounter;

    /**
     * Creates a discovery object that will perform a discovery algorithm
     * specified by the recognizer object, and will be applied to the given
     * SEService.
     *
     * @param service The SEService used to perform the discovery. Cannot be
     *        null.
     * @param recognizer An SERecognizer instance, whose isMatching method of
     *        the SERecognizer will be called. Cannot be null.
     *
     * @throws IllegalArgumentException If any of the parameters is null.
     */
    public SEDiscovery(SEService service, SERecognizer recognizer)
            throws IllegalArgumentException {
        if (service == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("service"));
        }
        if (recognizer == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("recognizer"));
        }

        mService = service;
        mRecognizer = recognizer;
        // Counter = -1 means that getFirstMatch has not been called yet.
        mCounter = -1;
    }

    /**
     * Returns the first Secure Element reader containing a Secure Element that
     * matches the search criterion.
     * <p>
     * Actually starts a full discovery process:
     * <p>
     * - Secure Element readers are enumerated
     * <p>
     * - For the first reader, if a Secure Element is present, open a session
     * <p>
     * - On this session, call the isMatching method of the SERecognizer object
     * given at construction time.
     * <p>
     * - The session is closed.
     * <p>
     * - If the isMatching method returns false, the process is continued with
     * the next reader.
     * <p>
     * - If the isMatching method returns true, the reader object is returned
     * <p>
     * The sessions used by the discovery process are closed to avoid the risk
     * of leaks: if they were opened and returned to the caller, there would be
     * a risk for the caller to forget to close them.
     * <p>
     * Calling getFirstMatch twice simply restarts the discovery process (e.g.
     * probably returns the same result, unless a Secure Element has been
     * removed).
     *
     * @return The first matching Secure Element reader, or null if there is
     *         none.
     */
    public Reader getFirstMatch() {
        // List all available readers
        mReaders = mService.getReaders();

        if ((mReaders == null) || (mReaders.length < 1)) {
            // If there are no readers, return null
            // Set counter to -1 to indicate that no match has been found.
            mCounter = -1;
            return null;
        }

        // Start an iteration through all the readers (notice that iteration
        // starts from counter = 0).
        mCounter = 0;
        try {
            return getNextMatch();
        } catch (IllegalStateException e) {
            // This will never happen since mCounter = 0.
            return null;
        }
    }

    /**
     * Returns the next Secure Element reader containing a Secure Element that
     * matches the search criterion.
     * <p>
     * Actually continues the discovery process:
     * <p>
     * - For the next reader in the enumeration, if a Secure Element is present,
     * open a session
     * <p>
     * - On this session, call the isMatching method of the SERecognizer object
     * given at construction time.
     * <p>
     * - The session is closed.
     * <p>
     * - If the isMatching method returns false, the process is continued with
     * the next reader.
     * <p>
     * - If the isMatching method returns true, the reader object is returned
     *
     * @return The next matching Secure Element reader, or null if there is
     *         none.
     *
     * @throws IllegalStateException if the getNextMatch() method is called without
     *         calling getFirstMatch() before, since the creation of the
     *         SEDiscovery object, or since the last call to getFirstMatch or
     *         getNextMatch that returned null.
     */
    public Reader getNextMatch() throws IllegalStateException {
        if (mCounter == -1) {
            throw new IllegalStateException(
                    "getFirstMatch needs to be called before getNextMatch()");
        }

        Reader nextReader;
        // Continue with the iteration started in getFirstMatch()
        for (; mCounter < mReaders.length; mCounter++) {
            // Set the next reader to be looked at.
            nextReader = mReaders[mCounter];
            if (nextReader.isSecureElementPresent()) {
                // If secure element is present, open session and check if
                // it matches
                try {
                    Session session = nextReader.openSession();
                    if (mRecognizer.isMatching(session)) {
                        session.close();
                        // Increase counter since when re-taking the iteration
                        // next reader must be get (not current one)
                        mCounter++;
                        return nextReader;
                    } else {
                        session.close();
                    }
                } catch (IOException e) {
                    // If session could not be opened, assume it is not matching
                    e.printStackTrace();
                } catch (IllegalArgumentException e) {
                    // If session is null, assume it is not matching
                    e.printStackTrace();
                }
            }
        }

        // Set counter to -1 to indicate that no match has been found.
        mCounter = -1;
        return null;
    }
}
