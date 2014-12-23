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

/**
 * Base class for recognizer classes. Extended by system-provided recognizers,
 * or by custom recognizers.
 */
public abstract class SERecognizer {

    /**
     * This is a call-back method that will be called during the discovery
     * process, once per Secure Element inserted in a reader. Application
     * developers can use the given session object to perform any discovery
     * algorithm they think is appropriate. They can use the Transport API or
     * any other API, conforming to access control rules & policy, like for
     * regular application code (i.e. this is not privileged code).
     *
     * @param session A Session object that is used to perform the discovery.
     *        Never null.
     *
     * @return A boolean indicating whether the Secure Element to which the
     *         given session has been open is matching with the recognition
     *         criterion implemented by this method.
     *
     * @throws IllegalArgumentException if the used session is null.
     */
    public abstract boolean isMatching(Session session)
            throws IllegalArgumentException;
}
