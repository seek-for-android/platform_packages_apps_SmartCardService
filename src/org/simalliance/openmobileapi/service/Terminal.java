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

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;

import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.pm.ResolveInfo;
import android.os.AsyncTask;
import android.os.IBinder;
import android.os.RemoteException;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.AccessControlException;
import java.util.ArrayList;
import java.util.NoSuchElementException;


import android.content.pm.PackageManager;
import android.util.Log;

import org.simalliance.openmobileapi.internal.Util;
import org.simalliance.openmobileapi.service.security.AccessControlEnforcer;
import org.simalliance.openmobileapi.service.security.ChannelAccess;

/**
 * Smartcard service base class for terminal resources.
 */
public class Terminal {

    private Context mContext;

    private final String mName;

    private ITerminalService mTerminalService;

    private ServiceConnection mTerminalConnection;

    private final ArrayList<Session> mSessions = new ArrayList<>();

    private final Object mLock = new Object();

    /* Async task */
    InitialiseTask mInitialiseTask;

    private BroadcastReceiver mSEReceiver;

     // TODO: this info should be stored persistently to persist on service restarts.
    private boolean mIsDefaultApplicationSelectedOnBasicChannel;

    /**
     * For each Terminal there will be one AccessController object.
     */
    private AccessControlEnforcer mAccessControlEnforcer;

    public Terminal(Context context, String name, ResolveInfo info) {
        mContext = context;
        mName = name;
        mIsDefaultApplicationSelectedOnBasicChannel = true;
        mTerminalConnection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
                mTerminalService = ITerminalService.Stub.asInterface(iBinder);
                mInitialiseTask = new InitialiseTask();
                mInitialiseTask.execute();
            }

            @Override
            public void onServiceDisconnected(ComponentName componentName) {
                mTerminalService = null;
                // Cancel the inialization background task if still running
                if (mInitialiseTask != null) {
                    mInitialiseTask.cancel(true);
                }
            }
        };

        mContext.bindService(
                new Intent().setClassName(info.serviceInfo.packageName, info.serviceInfo.name),
                mTerminalConnection,
                Context.BIND_AUTO_CREATE);
    }

    public SmartcardServiceReader getBinder() {
        return new SmartcardServiceReader();
    }

    private class InitialiseTask extends AsyncTask<Void, Void, Void> {

        @Override
        protected void onPreExecute() {
            super.onPreExecute();

        }

        @Override
        protected Void doInBackground(Void... arg0) {

            try {
                initializeAccessControl(false);
            } catch (Exception e) {
                // do nothing since this is called where nobody can react.
            }
            return null;
        }

        @Override
        protected void onPostExecute(Void result) {
            super.onPostExecute(result);
            registerSeStateChangedEvent();
            mInitialiseTask = null;
        }
    }

    public void registerSeStateChangedEvent() {
        Log.v(SmartcardService.LOG_TAG, "register to SE state change event");
        String action;
        try {
            action = mTerminalService.getSeStateChangedAction();
        } catch (RemoteException ignore) {
            Log.e(SmartcardService.LOG_TAG,
                    "Could not get SE State Changed Action, not registering to event",
                    ignore);
            return;
        }
        if (action == null) {
            return;
        }
        final String seStateChangedAction = action;
        IntentFilter intentFilter = new IntentFilter(seStateChangedAction);
        mSEReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (intent.getAction().equals(seStateChangedAction)) {
                    try {
                        if (mTerminalService.isCardPresent()) {
                            initializeAccessControl(true);
                        } else {
                            resetAccessControl();
                        }
                    } catch (RemoteException ignore) {
                        Log.w(SmartcardService.LOG_TAG,
                                "SE State Chaned receiver: Error calling isCardPresent, ignoring event",
                                ignore);
                    }

                }
            }
        };
        mContext.registerReceiver(mSEReceiver, intentFilter);
    }

    /**
     * Initalizes Access Control. At least the refresh tag is read and if it
     * differs to the previous one (e.g. is null) the all access rules are read.
     *
     * @param reset true to indicate that ACE should be reset.
     */
    public synchronized boolean initializeAccessControl(boolean reset) {
        Log.i(SmartcardService.LOG_TAG, "Initializing Access Control");

        boolean isCardPresent;
        try {
            isCardPresent = isCardPresent();
        } catch (Exception e) {
            isCardPresent = false;
        }

        if (isCardPresent) {
            Log.i(SmartcardService.LOG_TAG, "Initializing Access Control for " + getName());
            if (reset) {
                resetAccessControl();
            }
            if (mAccessControlEnforcer == null) {
                mAccessControlEnforcer = new AccessControlEnforcer(this);
            }
            return mAccessControlEnforcer.initialize(true, new ISmartcardServiceCallback.Stub(){});
        } else {
            Log.i(SmartcardService.LOG_TAG, "NOT initializing Access Control for " + getName()
                    + ": SE not present.");
            return true;
        }
    }

    public void onSmartcardServiceShutdown() {
        try {
            closeSessions();
        } catch (Exception ignore) {
            Log.w(SmartcardService.LOG_TAG, "Error during closeSessions()", ignore);
        }
        // Cancel the inialization background task if still running
        if (mInitialiseTask != null) {
            mInitialiseTask.cancel(true);
        }
        if(mSEReceiver != null) {
            mInitialiseTask = null;
            mContext.unregisterReceiver(mSEReceiver);
        }
        
        mSEReceiver = null;
        mContext.unbindService(mTerminalConnection);
    }

    public ISmartcardServiceSession openSession() throws Exception {
        if (!isCardPresent()) {
            throw new IOException("Secure Element is not presented.");
        }

        synchronized (mLock) {
            if (mAccessControlEnforcer == null || !mAccessControlEnforcer.isInitialized()) {
                initializeAccessControl(false);
            }
            Session session = new Session(this, mContext);
            mSessions.add(session);
            return session.getBinder();
        }
    }

    /**
     * Called when a session has been closed.
     *
     * @param session The session that has been closed.
     */
    void sessionClosed(Session session) {
        mSessions.remove(session);
    }

    private synchronized void closeSessions() throws Exception {
        while (mSessions.size() > 0) {
            mSessions.get(0).close();
        }
    }

    public Channel getBasicChannel() {
        for (Session session : mSessions) {
            Channel basicChannel = session.getBasicChannel();
            if (basicChannel != null) {
                return basicChannel;
            }
        }
        return null;
    }

    public String getName() {
        return mName;
    }

    /**
     * Implementation of the MANAGE CHANNEL open and SELECT commands.
     *
     * @param aid The aid of the applet to be selected.
     *
     * @return the number of the logical channel according to ISO 7816-4.
     *
     * @throws Exception If the channel could not be opened.
     */
    public OpenLogicalChannelResponse internalOpenLogicalChannel(byte[] aid, byte p2) throws Exception {
        SmartcardError error = new SmartcardError();
        OpenLogicalChannelResponse response = mTerminalService.internalOpenLogicalChannel(aid, p2, error);
        if (error.isSet()) {
            error.throwException();
        }
        return response;
    }

    /**
     * Implementation of the MANAGE CHANNEL close command.
     *
     * @param channelNumber The channel to be closed.
     *
     */
    public void internalCloseLogicalChannel(int channelNumber) throws Exception {
        if (channelNumber == 0) {
            // We need to deselect the applet selected in basic channel
            // TODO: this is a custom solution, this should be done according to spec once defined.
            try {
                // Try to select the default applet
                byte[] selectCommand = new byte[5];
                selectCommand[0] = 0x00;
                selectCommand[1] = (byte) 0xA4;
                selectCommand[2] = 0x04;
                selectCommand[3] = 0x00;
                selectCommand[4] = 0x00;
                transmit(selectCommand);
            } catch (Exception exp) {
                // Selection of the default application fails, try with ARA
                try {
                    Log.v(SmartcardService.LOG_TAG, "Close basic channel - Exception : "
                            + exp.getLocalizedMessage());
                    if (getAccessControlEnforcer() != null) {
                        byte[] aid = AccessControlEnforcer.getDefaultAccessControlAid();
                        byte[] selectCommand = new byte[aid.length + 6];
                        selectCommand[0] = 0x00;
                        selectCommand[1] = (byte) 0xA4;
                        selectCommand[2] = 0x04;
                        selectCommand[3] = 0x00;
                        selectCommand[4] = (byte) aid.length;
                        System.arraycopy(aid, 0, selectCommand, 5, aid.length);
                        // TODO: also accept 62XX and 63XX as valid SW
                        transmit(selectCommand);
                    }
                } catch (NoSuchElementException exp2) {
                    // Access Control Applet not available => Don't care
                }
            }
        }

        SmartcardError error = new SmartcardError();
        mTerminalService.internalCloseLogicalChannel(channelNumber, error);
        if (error.isSet()) {
            error.throwException();
        }
    }

    /**
     * Implements the terminal specific transmit operation.
     *
     * @param command the command APDU to be transmitted.
     * @return the response APDU received.
     */
    public byte[] internalTransmit(byte[] command) throws Exception {
        SmartcardError error = new SmartcardError();
        byte[] response = mTerminalService.internalTransmit(command, error);
        if (error.isSet()) {
            error.throwException();
        }
        return response;
    }

    /**
     * Returns the ATR of the connected card or null if the ATR is not
     * available.
     *
     * @return the ATR of the connected card or null if the ATR is not
     *         available.
     */
    public byte[] getAtr() {
        try {
            return mTerminalService.getAtr();
        } catch (RemoteException e) {
            Log.e(SmartcardService.LOG_TAG, "Error during getAtr()", e);
            return null;
        }
    }

    /**
     * Returns if the default application is selected on basic channel.
     *
     * @return the true if default application is selected on the basic channel.
     */
    public boolean isDefaultApplicationSelectedOnBasicChannel() {
        return mIsDefaultApplicationSelectedOnBasicChannel;
    }
    /**
     * Returns <code>true</code> if a card is present; <code>false</code>
     * otherwise.
     *
     * @return <code>true</code> if a card is present; <code>false</code>
     *         otherwise.
     */
    public boolean isCardPresent() {
        try {
            return mTerminalService.isCardPresent();
        } catch (RemoteException e) {
            Log.w(SmartcardService.LOG_TAG, "Error during isCardPresent()", e);
            return false;
        }
    }

    /**
     * Transmits the specified command and returns the response. Optionally
     * checks the response length and the response status word. The status word
     * check is implemented as follows (sw = status word of the response):
     * <p>
     * if ((sw & swMask) != (swExpected & swMask)) throw new CardException();
     * </p>
     *
     * @param cmd the command APDU to be transmitted.
     * @param minRspLength the minimum length of received response to be
     *            checked.
     * @param swExpected the response status word to be checked.
     * @param swMask the mask to be used for response status word comparison.
     * @param commandName the name of the smart card command for logging
     *            purposes. May be <code>null</code>.
     * @return the response received.
     */
    @Deprecated
    public synchronized byte[] transmit(
            byte[] cmd,
            int minRspLength,
            int swExpected,
            int swMask,
            String commandName) throws Exception {

        byte[] rsp= internalTransmit(cmd);
        if (rsp.length >= 2) {
            int sw1 = rsp[rsp.length - 2] & 0xFF;
            if (sw1 == 0x6C) {
                cmd[cmd.length - 1] = rsp[rsp.length - 1];
                rsp = internalTransmit(cmd);
            } else if (sw1 == 0x61) {
                byte[] getResponseCmd = new byte[] {
                        cmd[0], (byte) 0xC0, 0x00, 0x00, 0x00
                };
                byte[] response = new byte[rsp.length - 2];
                System.arraycopy(rsp, 0, response, 0, rsp.length - 2);
                while (true) {
                    getResponseCmd[4] = rsp[rsp.length - 1];
                    rsp = internalTransmit(getResponseCmd);
                    if (rsp.length >= 2 && rsp[rsp.length - 2] == 0x61) {
                        response = Util.appendResponse(
                                response, rsp, rsp.length - 2);
                    } else {
                        response = Util.appendResponse(response, rsp, rsp.length);
                        break;
                    }
                }
                rsp = response;
            }
        }
        if (minRspLength > 0) {
            if (rsp == null || rsp.length < minRspLength) {
                throw new IllegalStateException(
                        Util.createMessage(commandName, "response too small"));
            }
        }
        if (swMask != 0) {
            if (rsp == null || rsp.length < 2) {
                throw new IllegalArgumentException(
                        Util.createMessage(commandName, "SW1/2 not available"));
            }
            int sw1 = rsp[rsp.length - 2] & 0xFF;
            int sw2 = rsp[rsp.length - 1] & 0xFF;
            int sw = (sw1 << 8) | sw2;
            if ((sw & swMask) != (swExpected & swMask)) {
                throw new IllegalArgumentException(Util.createMessage(commandName, sw));
            }
        }
        if ("SELECT ON BASIC CHANNEL".equalsIgnoreCase(commandName)) {
            mIsDefaultApplicationSelectedOnBasicChannel = false;
        }
        return rsp;
    }

    /**
     * Transmits the specified command and returns the response. If response is SW 61XX, sends a GET
     * RESPONSE. If response is SW 6C XX, resends the command with the appropriate Le.
     *
     * @param cmd the command APDU to be transmitted.
     *
     * @return the response received.
     */
    public synchronized byte[] transmit(byte[] cmd) throws Exception {

        byte[] rsp = internalTransmit(cmd);
        if (rsp.length < 2) {
            throw new IOException("Unexpected response length");
        }

        int sw1 = rsp[rsp.length - 2] & 0xFF;
        int sw2 = rsp[rsp.length - 1] & 0xFF;
        if (sw1 == 0x6C) {
            cmd[cmd.length - 1] = rsp[rsp.length - 1];
            rsp = internalTransmit(cmd);
        } else if (sw1 == 0x61) {
            do {
                byte[] getResponseCmd = new byte[]{
                        cmd[0], (byte) 0xC0, 0x00, 0x00, (byte) sw2
                };
                byte[] tmp = internalTransmit(getResponseCmd);
                byte[] aux = rsp;
                rsp = new byte[aux.length + tmp.length - 2];
                System.arraycopy(aux, 0, rsp, 0, aux.length - 2);
                System.arraycopy(tmp, 0, rsp, aux.length - 2, tmp.length);
                sw1 = rsp[rsp.length - 2] & 0xFF;
                sw2 = rsp[rsp.length - 1] & 0xFF;
            } while (sw1 == 0x61);
        }
        if (isSelectOnBasicChannel(cmd)
                && ((sw1 == 0x90 && sw2 == 0x00)
                    || sw1 == 0x62
                    || sw1 == 0x63)) {
            Log.d(SmartcardService.LOG_TAG, "Select on basic channel succeeded on reader " + getName());
            mIsDefaultApplicationSelectedOnBasicChannel = false;
        }
        return rsp;
    }

    /**
     * Check whether a command is a SELECT by AID sent to the basic channel.
     *
     * @param cmd The command to be checked.
     *
     * @return true if cmd is a SELECT by AID sent to the basic channel, false otherwise.
     */
    private boolean isSelectOnBasicChannel(byte[] cmd) {
        return (cmd[0] & 0x03) == 0x00 && (cmd[1] & 0xFF) == 0xA4 && (cmd[2] & 0xFF) == 0x04;
    }

    public byte[] simIOExchange(int fileID, String filePath, byte[] cmd)
            throws Exception {
        SmartcardError error = new SmartcardError();
        try {
            return mTerminalService.simIOExchange(fileID, filePath, cmd, error);
        } catch (RemoteException e) {
            throw new IOException("SIM IO error!");
        }
    }

    public ChannelAccess setUpChannelAccess(
            PackageManager packageManager,
            byte[] aid,
            String packageName) {
        if (mAccessControlEnforcer == null) {
            throw new AccessControlException(
                    "Access Control Enforcer not properly set up");
        }
        mAccessControlEnforcer.setPackageManager(packageManager);
        return mAccessControlEnforcer.setUpChannelAccess(aid, packageName);
    }

    public AccessControlEnforcer getAccessControlEnforcer() {
        return mAccessControlEnforcer;
    }

    private synchronized void resetAccessControl() {
        if (mAccessControlEnforcer != null) {
            mAccessControlEnforcer.reset();
        }
    }


    /**
     * Implementation of the SmartcardService Reader interface according to
     * OMAPI.
     */
    private class SmartcardServiceReader extends ISmartcardServiceReader.Stub {

        @Override
        public boolean isSecureElementPresent() throws RemoteException {
            return Terminal.this.isCardPresent();
        }

        @Override
        public ISmartcardServiceSession openSession(SmartcardError error) throws RemoteException {
            try {
                return Terminal.this.openSession();
            } catch (Exception e) {
                Log.e(SmartcardService.LOG_TAG, "Error during openSession()", e);
                error.set(e);
                return null;
            }
        }

        @Override
        public void closeSessions(SmartcardError error) throws RemoteException {
            try {
                Terminal.this.closeSessions();
            } catch (Exception e) {
                Log.e(SmartcardService.LOG_TAG, "Error during closeSessions()", e);
                error.set(e);
            }
        }
    }

    public void dump(PrintWriter writer, String prefix) {
        writer.println(prefix + "SMARTCARD SERVICE TERMINAL: " + getName());
        writer.println();

        prefix += "  ";

        writer.println(prefix + "mIsConnected:" + (mTerminalService != null));
        writer.println();

        /* Dump the list of currunlty openned channels */
        writer.println(prefix + "List of open channels:");

        for (Session session : mSessions) {
            if (session != null && !session.isClosed()) {
                session.dump(writer, prefix);
            }
        }

        writer.println();

        /* Dump ACE data */
        if (mAccessControlEnforcer != null) {
            mAccessControlEnforcer.dump(writer, prefix);
        }
    }
}
