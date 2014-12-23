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
 * This Provider abstract class is the base class for all service layer classes.
 * Each service layer class provides a set of methods for a certain aspect (file
 * management, PIN authentication, PKCS#15 structure handling, ...) and acts as
 * a provider for service routines. All Provider classes need an opened channel
 * for the SE communication. Hence before a certain Provider class can be used
 * for SE operations the channel has to be consigned. For performing different
 * operations (PIN authentication, file operation, ...) the Provider classes can
 * be easily combined by using the same channel for different Provider classes
 * and calling alternately methods of these different providers. It has to be
 * considered that each provider class needs a counterpart on SE side (e.g. an
 * Applet with a standardised APDU interface as required by the Provider class).
 * The application using a Provider class for SE interactions is in charge of
 * assigning a channel to the Provider where the Provider's SE counterpart
 * Applet is already preselected.
 */
public abstract class Provider {

    /**
     * Currently used channel, while creating the object.
     */
    private Channel mChannel;

    /**
     * Encapsulates the defined channel by a Provider object that can be used
     * for performing a service operations on it. This constructor has to be
     * called by derived Provider classes during the instantiation.
     *
     * @param channel The channel that shall be used by this Provider for
     *        service operations.
     *
     * @throws IllegalStateException if the used channel is closed.
     */
    public Provider(Channel channel) throws IllegalStateException {
        if (channel == null) {
            throw new IllegalStateException(ErrorStrings.paramNull("channel"));
        }

        if (channel.isClosed()) {
            throw new IllegalStateException(ErrorStrings.CHANNEL_CLOSED);
        }

        mChannel = channel;
    }

    /**
     * Returns the channel that is used by this provider. This returned channel
     * can also be used by other providers.
     *
     * @return The channel instance that is used by this provider.
     */
    public Channel getChannel() {
        return mChannel;
    }
}
