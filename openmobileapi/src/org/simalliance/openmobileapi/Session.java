/*
 * Copyright (C) 2011, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Contributed by: Giesecke & Devrient GmbH.
 */

package org.simalliance.openmobileapi;

import java.io.IOException;
import java.util.MissingResourceException;
import java.util.NoSuchElementException;

import org.simalliance.openmobileapi.service.ISmartcardServiceChannel;
import org.simalliance.openmobileapi.service.ISmartcardServiceSession;
import org.simalliance.openmobileapi.service.SmartcardError;

import android.os.RemoteException;

/**
 * Instances of this class represent a connection session to one of the secure
 * elements available on the device. These objects can be used to get a
 * communication channel with an application in the secure element. This channel
 * can be the basic channel or a logical channel.
 *
 * @see <a href="http://simalliance.org">SIMalliance Open Mobile API v2.02</a>
 */
public class Session {

    private final Object mLock = new Object();
    private final SEService mService;
    private final Reader mReader;
    private final ISmartcardServiceSession mSession;

    Session(SEService service,
            ISmartcardServiceSession session,
            Reader reader) {
        mService = service;
        mReader = reader;
        mSession = session;
    }

    /**
     * Get the reader that provides this session.
     *
     * @return The Reader object.
     */
    public Reader getReader() {
        return mReader;
    }

    /**
     * Get the Answer to Reset of this Secure Element. <br>
     * The returned byte array can be null if the ATR for this Secure Element is
     * not available.
     *
     * @return the ATR as a byte array or null.
     */
    public byte[] getATR() {
        if (mService == null || !mService.isConnected()) {
            throw new IllegalStateException("service not connected to system");
        }
        if (mSession == null) {
            throw new IllegalStateException("service session is null");
        }
        try {
            return mSession.getAtr();
        } catch (RemoteException e) {
            throw new IllegalStateException(e.getMessage());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Close the connection with the Secure Element. This will close any
     * channels opened by this application with this Secure Element.
     */
    public void close() {
        if (mService == null || !mService.isConnected()) {
            throw new IllegalStateException("service not connected to system");
        }
        if (mSession != null) {
            synchronized (mLock) {
                SmartcardError error = new SmartcardError();
                try {
                    mSession.close(error);
                } catch (RemoteException e) {
                    throw new IllegalStateException(e.getMessage());
                }
                SEService.checkForException(error);
            }
        }
    }

    /**
     * Tells if this session is closed.
     *
     * @return <code>true</code> if the session is closed, false otherwise.
     */
    public boolean isClosed() {
        try {
            if (mSession == null) {
                return true;
            }
            return mSession.isClosed();
        } catch (RemoteException e) {
            throw new IllegalStateException(e.getMessage());
        }
    }

    /**
     * Close any channel opened on this session.
     *
     * @throws IOException
     */
    public void closeChannels() {

        if (mService == null || !mService.isConnected()) {
            throw new IllegalStateException("service not connected to system");
        }

        if (mSession != null) {
            synchronized (mLock) {
                SmartcardError error = new SmartcardError();
                try {
                    mSession.closeChannels(error);
                } catch (RemoteException e) {
                    throw new IllegalStateException(e.getMessage());
                }
                SEService.checkForException(error);
            }
        }
    }

    /**
     * Get an access to the basic channel, as defined in the ISO/IEC 7816-4
     * specification (the one that has number 0). The obtained object is an
     * instance of the Channel class. If the AID is null, which means no Applet
     * is to be selected on this channel and the default Applet is used. If the
     * AID is defined then the corresponding Applet is selected. Once this
     * channel has been opened by a device application, it is considered as
     * "locked" by this device application, and other calls to this method will
     * return null, until the channel is closed. Some Secure Elements (like the
     * UICC) might always keep the basic channel locked (i.e. return null to
     * applications), to prevent access to the basic channel, while some other
     * might return a channel object implementing some kind of filtering on the
     * commands, restricting the set of accepted command to a smaller set. It is
     * recommended for the UICC to reject the opening of the basic channel to a
     * specific Applet, by always answering null to such a request. For other
     * Secure Elements, the recommendation is to accept opening the basic
     * channel on the default Applet until another Applet is selected on the
     * basic channel. As there is no other way than a reset to select again the
     * default Applet, the implementation of the transport API should guarantee
     * that the openBasicChannel(null) command will return null until a reset
     * occurs. If such a restriction is not possible, then
     * openBasicChannel(null) should always return null and therefore prevent
     * access to the default Applet on the basic channel.
     * <p>
     * The optional select response data of an applet can be retrieved with
     * byte[] getSelectResponse().
     *
     * @param aid the AID of the Applet to be selected on this channel, as a
     *            byte array, or null if no Applet is to be selected.
     * @throws IOException if there is a communication problem to the reader or
     *             the Secure Element (e.g. if the SE is not responding).
     * @throws IllegalStateException if the Secure Element session is used after
     *             being closed.
     * @throws IllegalArgumentException if the aid's length is not within 5 to
     *             16 (inclusive).
     * @throws SecurityException if the calling application cannot be granted
     *             access to this AID or the default application on this
     *             session.
     * @throws NoSuchElementException if an Applet with the defined AID does not
     *             exist in the SE
     * @return an instance of Channel if available or null.
     */
    public Channel openBasicChannel(byte[] aid) throws IOException {

        if (mService == null || !mService.isConnected()) {
            throw new IllegalStateException("service not connected to system");
        }
        if (mSession == null) {
            throw new IllegalStateException("service session is null");
        }
        if (getReader() == null) {
            throw new IllegalStateException("reader must not be null");
        }

        synchronized (mLock) {
            ISmartcardServiceChannel channel;
            SmartcardError error = new SmartcardError();
            try {
                channel = mSession.openBasicChannelAid(
                        aid,
                        mService.getCallback(),
                        error);
            } catch (RemoteException e) {
                throw new IllegalStateException(e.getMessage());
            } catch (Exception e) {
                throw new IOException(e.getMessage());
            }
            if (isBasicChannelInUse(error)) {
                return null;
            }
            if (aid == null || aid.length == 0) {
                if (!isDefaultApplicationSelected(error)) {
                    return null;
                }
            }
            SEService.checkForException(error);
            error.clear();
            boolean b = channelCannotBeEstablished(error);
            SEService.checkForException(error);
            if (b) {
                return null;
            }
            error.clear();
            checkIfAppletAvailable(error);
            SEService.checkForException(error);

            if (channel == null) {
                return null;
            }

            return new Channel(mService, this, channel);
        }
    }

    /**
     * Open a logical channel with the Secure Element, selecting the Applet
     * represented by the given AID. The AID can be null, which means no Applet
     * is to be selected on this channel, the default Applet is used. It's up to
     * the Secure Element to choose which logical channel will be used.
     * <p>
     * The optional select response data of an applet can be retrieved with
     * byte[] getSelectResponse().
     * <p>
     * A logical channel to an applet can be opened multiple times if the applet
     * implements MultiSelectable.
     *
     * @param aid the AID of the Applet to be selected on this channel, as a
     *            byte array.
     * @throws IOException if there is a communication problem to the reader or
     *             the Secure Element. (e.g. if the SE is not responding)
     * @throws IllegalStateException if the Secure Element is used after being
     *             closed.
     * @throws IllegalArgumentException if the aid's length is not within 5 to
     *             16 (inclusive).
     * @throws SecurityException if the calling application cannot be granted
     *             access to this AID or the default application on this
     *             session.
     * @throws NoSuchElementException if an Applet with the defined AID does not
     *             exist in the SE or a logical channel is already open to a
     *             non-multiselectable applet
     * @return an instance of Channel. Null if the Secure Element is unable to
     *         provide a new logical channel.
     */
    public Channel openLogicalChannel(byte[] aid) throws IOException {

        if (mService == null || !mService.isConnected()) {
            throw new IllegalStateException("service not connected to system");
        }
        if (mSession == null) {
            throw new IllegalStateException("service session is null");
        }
        if (getReader() == null) {
            throw new IllegalStateException("reader must not be null");
        }
        synchronized (mLock) {
            SmartcardError error = new SmartcardError();
            ISmartcardServiceChannel channel;
            try {
                channel = mSession.openLogicalChannel(
                        aid,
                        mService.getCallback(),
                        error);
            } catch (RemoteException e) {
                throw new IllegalStateException(e.getMessage());
            } catch (Exception e) {
                throw new IOException(e.getMessage());
            }
            SEService.checkForException(error);
            error.clear();
            boolean b = channelCannotBeEstablished(error);
            SEService.checkForException(error);
            if (b) {
                return null;
            }
            error.clear();
            checkIfAppletAvailable(error);
            SEService.checkForException(error);

            if (channel == null) {
                return null;
            }

            return new Channel(mService, this, channel);
        }
    }

    // ******************************************************************
    // package private methods
    // ******************************************************************

    private boolean isDefaultApplicationSelected(SmartcardError error) {
        Exception exp = error.createException();
        if (exp != null) {
            String msg = exp.getMessage();
            if (msg != null) {
                if (msg.contains("default application is not selected")) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean isBasicChannelInUse(SmartcardError error) {
        Exception exp = error.createException();
        if (exp != null) {
            String msg = exp.getMessage();
            if (msg != null) {
                if (msg.contains("basic channel in use")) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean channelCannotBeEstablished(SmartcardError error) {
        Exception exp = error.createException();
        if (exp != null) {
            if (exp instanceof MissingResourceException) {
                return true;
            }
            String msg = exp.getMessage();
            if (msg != null) {
                if (msg.contains("channel in use")) {
                    return true;
                }
                if (msg.contains("open channel failed")) {
                    return true;
                }
                if (msg.contains("out of channels")) {
                    return true;
                }
                if (msg.contains("MANAGE CHANNEL")) {
                    return true;
                }
            }
        }
        return false;
    }

    private void checkIfAppletAvailable(SmartcardError error)
            throws NoSuchElementException {
        Exception exp = error.createException();
        if (exp != null) {
            if (exp instanceof NoSuchElementException) {
                throw new NoSuchElementException(
                        "Applet with the defined aid does not exist in the SE");
            }
        }
    }

}
