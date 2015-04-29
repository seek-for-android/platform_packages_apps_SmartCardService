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

package org.simalliance.openmobileapi.service;

import android.os.Binder;
import android.os.IBinder;
import android.os.RemoteException;

import android.util.Log;

import org.simalliance.openmobileapi.service.security.ChannelAccess;
import org.simalliance.openmobileapi.util.CommandApdu;
import org.simalliance.openmobileapi.util.ResponseApdu;
import org.simalliance.openmobileapi.util.ISO7816;

/**
 * Smartcard service base class for channel resources.
 */
public class Channel implements IBinder.DeathRecipient {

    protected final int mChannelNumber;

    protected boolean mIsClosed;

    protected long mHandle;

    protected Session mSession;

    protected byte[] mSelectResponse;

    protected final IBinder mBinder;

    protected ChannelAccess mChannelAccess = null;

    protected ISmartcardServiceCallback mCallback;

    protected boolean mHasSelectedAid = false;
    protected byte[] mAid = null;

    /**
     * Creates a Channel object.
     *
     * @param session The session that created this channel.
     * @param channelNumber The channel number.
     * @param selectResponse The response to the select command (if any).
     * @param callback
     */
    public Channel(Session session,
            int channelNumber,
            byte[] selectResponse,
            ISmartcardServiceCallback callback) {
        this.mChannelNumber = channelNumber;
        this.mSession = session;
        this.mCallback = callback;
        this.mBinder = callback.asBinder();
        this.mSelectResponse = selectResponse;
        this.mIsClosed = false;
        try {
            mBinder.linkToDeath(this, 0);
        } catch (RemoteException e) {
            Log.e(SmartcardService.LOG_TAG, "Failed to register client callback");
        }
    }

    public SmartcardServiceChannel getBinder() {
        return new SmartcardServiceChannel();
    }

    public void binderDied() {
        // Close this channel if the client died.
        try {
            Log.e(SmartcardService.LOG_TAG, Thread.currentThread().getName()
                    + " Client " + mBinder.toString() + " died");
            close();
        } catch (Exception ignore) {
        }
    }

    public synchronized void close() throws Exception {
        mSession.closeChannel(getChannelNumber());
        mIsClosed = true;
        mBinder.unlinkToDeath(this, 0);
    }

    public int getChannelNumber() {
        return mChannelNumber;
    }

    /**
     * Returns if this channel is a basic channel.
     *
     * @return true if this channel is a basic channel
     */
    public boolean isBasicChannel() {
        return (mChannelNumber == 0);
    }

    public ISmartcardServiceCallback getCallback() {
        return mCallback;
    }

    /**
     * Returns the handle assigned to this channel.
     *
     * @return the handle assigned to this channel.
     */
    long getHandle() {
        return mHandle;
    }

    /**
     * Assigns the channel handle.
     *
     * @param handle the channel handle to be assigned.
     */
    void setHandle(long handle) {
        this.mHandle = handle;
    }

    public byte[] transmit(byte[] command) throws Exception {

        if (isClosed()) {
            throw new IllegalStateException("Channel is closed");
        }

        if (command == null) {
            throw new NullPointerException("Command must not be null");
        }

        if (command.length < 4) {
            throw new IllegalArgumentException("Command must have at least 4 bytes");
        }

        if (mChannelAccess == null) {
            throw new SecurityException("Channel access not set.");
        }

        if (mChannelAccess.getCallingPid() != Binder.getCallingPid()) {
            throw new SecurityException("Wrong Caller PID.");
        }

        if (((command[0] & (byte) 0x80) == 0)
                && ((byte) (command[0] & (byte) 0x60) != (byte) 0x20)) {
            // ISO command
            if (command[1] == (byte) 0x70) {
                throw new SecurityException(
                        "MANAGE CHANNEL command not allowed");
            }
            if ((command[1] == (byte) 0xA4) && (command[2] == (byte) 0x04)) {
                throw new SecurityException(
                        "SELECT by DF name command not allowed");
            }
        }

        // set channel number bits
        command[0] = Util.setChannelToClassByte(command[0], mChannelNumber);

        CommandApdu cApdu = new CommandApdu(command);
        checkCommand(command);

        if (cApdu.isExtendedLength()
                && command.length != ISO7816.CMD_APDU_LENGTH_CASE2_EXTENDED) {
            return transmitExtendedCommand(cApdu.toByteArray());
        } else {
            return mSession.transmit(cApdu.toByteArray(), 2, 0, 0, null);
        }
    }

    public byte[] transmitExtendedCommand(byte[] command) throws Exception {
        byte[] envelopeData;
        byte[] response;
        int pos = 0;
        while ((pos +  ISO7816.MAX_COMMAND_DATA_LENGTH_NO_EXTENDED) < command.length) {
            envelopeData = new byte[ISO7816.MAX_COMMAND_DATA_LENGTH_NO_EXTENDED];
            System.arraycopy(
                    command, pos, envelopeData, 0, envelopeData.length);
            mSession.transmit(new CommandApdu(
                    command[ISO7816.OFFSET_CLA],
                    (byte) 0xC2,
                    (byte) 0x00,
                    (byte) 0x00,
                    envelopeData).toByteArray(), 2, 0, 0, null);
            pos += ISO7816.MAX_COMMAND_DATA_LENGTH_NO_EXTENDED;
        }
        // Last request
        envelopeData = new byte[command.length - pos];
        if (envelopeData.length != 0) {
            System.arraycopy(
                    command, pos, envelopeData, 0, envelopeData.length);
            mSession.transmit(new CommandApdu(
                    command[ISO7816.OFFSET_CLA],
                    (byte) 0xC2,
                    (byte) 0x00,
                    (byte) 0x00,
                    envelopeData).toByteArray(), 2, 0, 0, null);
        }
        // Start get data envelope
        response = mSession.transmit(new CommandApdu(
                command[ISO7816.OFFSET_CLA],
                (byte) 0xC2,
                (byte) 0x00,
                (byte) 0x00,
                0).toByteArray(), 2, 0, 0, null);
        return response;
    }

    public boolean selectNext() throws Exception {

        if (isClosed()) {
            throw new IllegalStateException("Channel is closed");
        }

        if (mChannelAccess == null) {
            throw new SecurityException("Channel access not set.");
        }

        if (mChannelAccess.getCallingPid() != Binder.getCallingPid()) {
            throw new SecurityException(" Wrong Caller PID. ");
        }

        if (mAid == null || mAid.length == 0) {
            throw new IllegalArgumentException("No AID given");
        }

        mSelectResponse = null;
        byte[] selectCommand = new byte[5 + mAid.length];
        selectCommand[0] = 0x00;
        selectCommand[1] = (byte) 0xA4;
        selectCommand[2] = 0x04;
        selectCommand[3] = 0x02; // next occurrence
        selectCommand[4] = (byte) mAid.length;
        System.arraycopy(mAid, 0, selectCommand, 5, mAid.length);

        // set channel number bits
        selectCommand[0] = Util.setChannelToClassByte(selectCommand[0], mChannelNumber);

        mSelectResponse = mSession.transmit(selectCommand, 2, 0, 0, "SELECT NEXT");

        int sw1 = mSelectResponse[mSelectResponse.length - 2] & 0xFF;
        int sw2 = mSelectResponse[mSelectResponse.length - 1] & 0xFF;
        int sw = (sw1 << 8) | sw2;
        if (((sw & 0xF000) == 0x9000) || ((sw & 0xFF00) == 0x6200)
                || ((sw & 0xFF00) == 0x6300)){
            return true;
        } else if (sw == 0x6A82) {
            mSelectResponse = null;
            return false;
        } else {
            throw new UnsupportedOperationException("Unsupported operation");
        }
    }

    public void setChannelAccess(ChannelAccess channelAccess) {
        mChannelAccess = channelAccess;
    }

    public ChannelAccess getChannelAccess() {
        return this.mChannelAccess;
    }

    private void checkCommand(byte[] command) {
        if (mSession.getReader().getAccessControlEnforcer() == null) {
            throw new SecurityException("FATAL: Access Controller Enforcer not set for Terminal: "
                                            + mSession.getReader().getName());
        }

        // check command if it complies to the access rules.
        // if not an exception is thrown
        mSession.getReader().getAccessControlEnforcer().checkCommand(this, command);

    }

    /**
     * set selected aid flag and aid (may be null).
     * TODO: this method should be removed and AID be set in constructor
     */
    public void hasSelectedAid(boolean has, byte[] aid) {
        mHasSelectedAid = has;
        mAid = aid;
    }

    /**
     * Returns the data as received from the application select command
     * inclusively the status word. The returned byte array contains the data
     * bytes in the following order: [<first data byte>, ..., <last data byte>,
     * <sw1>, <sw2>]
     *
     * @return The data as returned by the application select command
     *         inclusively the status word.
     * @return Only the status word if the application select command has no
     *         returned data.
     * @return null if an application select command has not been performed or
     *         the selection response can not be retrieved by the reader
     *         implementation.
     */
    public byte[] getSelectResponse() {
        return mSelectResponse;
    }

    boolean isClosed() {
        return mIsClosed;
    }

    /**
     * Implementation of the SmartcardService Channel interface according to
     * OMAPI.
     */
    private class SmartcardServiceChannel extends ISmartcardServiceChannel.Stub {

        @Override
        public void close(SmartcardError error) throws RemoteException {
            try {
                Channel.this.close();
            } catch (Exception e) {
                Log.e(SmartcardService.LOG_TAG, "Error during close()", e);
                error.set(e);
            }
        }

        @Override
        public boolean isClosed() throws RemoteException {
            return Channel.this.isClosed();
        }

        @Override
        public boolean isBasicChannel() throws RemoteException {
            return Channel.this.isBasicChannel();
        }

        @Override
        public byte[] getSelectResponse() throws RemoteException {
            return Channel.this.getSelectResponse();
        }

        @Override
        public byte[] transmit(byte[] command, SmartcardError error) throws RemoteException {
            try {
                return Channel.this.transmit(command);
            } catch (Exception e) {
                Log.e(SmartcardService.LOG_TAG, "Error during transmit()", e);
                error.set(e);
                return null;
            }
        }

        @Override
        public boolean selectNext(SmartcardError error) throws RemoteException {
            try {
                return Channel.this.selectNext();
            } catch (Exception e) {
                Log.e(SmartcardService.LOG_TAG, "Error during selectNext()", e);
                error.set(e);
                return false;
            }
        }
    }
}
