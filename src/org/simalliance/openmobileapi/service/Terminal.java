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
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Random;


import android.content.pm.PackageManager;
import android.util.Log;

import org.simalliance.openmobileapi.service.security.AccessControlEnforcer;
import org.simalliance.openmobileapi.service.security.ChannelAccess;


/**
 * Smartcard service base class for terminal resources.
 */
public class Terminal {

    /** Random number generator used for handle creation. */
    static Random mRandom = new Random();

    private static final String _TAG = "Terminal";

    protected Context mContext;

    private final Map<Long, Channel> mChannels = new HashMap<Long, Channel>();

    protected final String mName;

    protected int mIndex;

    protected ITerminalService mTerminalService;

    protected ServiceConnection mTerminalConnection;

    protected byte[] mSelectResponse;

    private final ArrayList<Session> mSessions
            = new ArrayList<Session>();

    private final Object mLock = new Object();

    /* Async task */
    InitialiseTask mInitialiseTask;

    private BroadcastReceiver mSEReceiver;

    protected boolean mDefaultApplicationSelectedOnBasicChannel = true;

 
    /**
     * For each Terminal there will be one AccessController object.
     */
    private AccessControlEnforcer mAccessControlEnforcer;

    public Terminal(Context context, String name, ResolveInfo info) {
        mContext = context;
        mName = name;
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
            }
        };

        mContext.bindService(
                new Intent().setClassName(info.serviceInfo.packageName,
                        info.serviceInfo.name),
                mTerminalConnection,
                Context.BIND_AUTO_CREATE);
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
            registerSEStateChangedEvent();
            mInitialiseTask = null;
        }
    }

    public void registerSEStateChangedEvent() {
        Log.v(_TAG, "register to SE state change event");
        try {
            IntentFilter intentFilter = new IntentFilter(
                    mTerminalService.getSEChangeAction());
            mSEReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    try {
                        if (mTerminalService.getSEChangeAction().equals(intent
                                .getAction())) {
                            initializeAccessControl(
                                    true);
                        }
                    }
                    catch(RemoteException e) {
                        e.printStackTrace();
                    }
                }
            };
            mContext.registerReceiver(mSEReceiver, intentFilter);
        } catch(RemoteException e) {
            e.printStackTrace();
        }
    }

    /**
     * Initalizes Access Control. At least the refresh tag is read and if it
     * differs to the previous one (e.g. is null) the all access rules are read.
     *
     * @param reset
     */
    public synchronized boolean initializeAccessControl(
            boolean reset) {
        boolean result = true;
        Log.i(_TAG, "Initializing Access Control");

        boolean isCardPresent;
        try {
            isCardPresent = isCardPresent();
        } catch (Exception e) {
            isCardPresent = false;

        }

        if (isCardPresent) {
            Log.i(_TAG,
                    "Initializing Access Control for "
                            + getName());
            if (reset) {
                resetAccessControl();
            }
            result &= initializeAccessControl(true, new ISmartcardServiceCallback.Stub() {});
        } else {
            Log.i(_TAG, "NOT initializing Access Control for "
                    + getName() + " SE not present.");
        }

        return result;
    }

    public void onSmartcardServiceShutdown() {
        closeChannels();
        // Cancel the inialization background task if still running
        if (mInitialiseTask != null) {
            mInitialiseTask.cancel(true);
        }
        mInitialiseTask = null;
        mContext.unregisterReceiver(mSEReceiver);
        mSEReceiver = null;
        mContext.unbindService(mTerminalConnection);
    }

    /**
     * Closes the defined Session and all its allocated resources. <br>
     * After calling this method the Session can not be used for the
     * communication with the Secure Element any more.
     *
     * @param session the Session that should be closed
     * @throws RemoteException
     * @throws CardException
     * @throws NullPointerException if Session is null
     */
    synchronized void closeSession(Session session)
            throws RemoteException, CardException {
        if (session == null) {
            throw new NullPointerException("session is null");
        }
        if (!session.isClosed()) {
            SmartcardError error = new SmartcardError();
            session.closeChannels(error);
            error.throwException();
            session.setClosed();
        }
        mSessions.remove(session);
    }

    private void closeSessions(SmartcardError error) throws RemoteException, CardException {
        synchronized (mLock) {
            Iterator<Session> iter = mSessions.iterator();
            while (iter.hasNext()) {
                Session session = iter.next();
                closeSession(session);
                iter = mSessions.iterator();
            }
            mSessions.clear();
        }
    }

    /**
     * This method is called in SmartcardService:onDestroy
     * to clean up all open channels.
     */
    public synchronized void closeChannels() {
        Collection<Channel> col = mChannels.values();
        Channel[] channelList = col.toArray(new Channel[col.size()]);
        for (Channel channel : channelList) {
            try {
                closeChannel(channel);
            } catch (Exception ignore) {
            }
        }
    }

    /**
     * Closes the specified channel.
     *
     * @param channel the channel to be closed.
     * @throws CardException if closing the channel failed.
     */
    public synchronized void closeChannel(Channel channel)
            throws Exception {

        try {
            internalCloseLogicalChannel(channel.getChannelNumber());
        } finally {
            mChannels.remove(channel.getHandle());
        }
    }

    /**
     * Creates a channel instance.
     *
     * @param channelNumber the channel number according to ISO 7816-4.
     * @param callback the callback used to detect the death of the client.
     * @return a channel instance.
     */
    protected Channel createChannel(
            Session session,
            int channelNumber,
            ISmartcardServiceCallback callback) {
        return new Channel(session, this, channelNumber, callback);
    }

    private Channel getBasicChannel() {
        for (Channel channel : mChannels.values()) {
            if (channel.getChannelNumber() == 0) {
                return channel;
            }
        }
        return null;
    }

    public synchronized Channel getChannel(long hChannel) {
        return mChannels.get(hChannel);
    }

    public String getName() {
        return mName;
    }

    /**
     * Implementation of the SELECT command.
     *
     * @return the number of the logical channel according to ISO 7816-4.
     *
     * @throws Exception If the channel could not be opened.
     */
    protected int internalOpenLogicalChannel() throws Exception {
        SmartcardError error = new SmartcardError();
        try {
            OpenLogicalChannelResponse response = mTerminalService.internalOpenLogicalChannel(null, error);
            Exception ex = error.createException();
            if(ex != null) {
                throw ex;
            }
            mSelectResponse = response.getSelectResponse();
            return response.getChannel();
        } catch(RemoteException e) {
            error.throwException();
            throw e;
        }
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
    protected int internalOpenLogicalChannel(byte[] aid)
            throws Exception {
        SmartcardError error = new SmartcardError();
        try {
            OpenLogicalChannelResponse response = mTerminalService.internalOpenLogicalChannel(aid, error);
            Exception ex = error.createException();
            if(ex != null) {
                throw ex;
            }
            mSelectResponse = response.getSelectResponse();
            return response.getChannel();
        } catch(RemoteException e) {
            error.throwException();
            throw e;
        }
    }

    /**
     * Implementation of the MANAGE CHANNEL close command.
     *
     * @param channelNumber The channel to be closed.
     *
     * @throws CardException If the channel could not be closed.
     */
    protected void internalCloseLogicalChannel(int channelNumber)
            throws CardException {
        SmartcardError error = new SmartcardError();
        try {
            mTerminalService.internalCloseLogicalChannel(channelNumber, error);
            error.throwException();
        } catch(RemoteException e) {
            error.throwException();
        }
    }

    /**
     * Implements the terminal specific transmit operation.
     *
     * @param command the command APDU to be transmitted.
     * @return the response APDU received.
     * @throws CardException if the transmit operation failed.
     */
    protected byte[] internalTransmit(byte[] command)
            throws CardException {
        SmartcardError error = new SmartcardError();
        try {
            byte[] response = mTerminalService.internalTransmit(command, error);
            error.throwException();
            return response;
        } catch(RemoteException e) {
            error.throwException();
            throw new CardException("Remote Exception");
        }
    }

    /**
     * Returns the ATR of the connected card or null if the ATR is not
     * available.
     *
     * @return the ATR of the connected card or null if the ATR is not
     *         available.
     */
    public byte[] getAtr() {
        try{
            return mTerminalService.getAtr();
        } catch (RemoteException e) {
            return null;
        }
    }

    /**
     * Returns <code>true</code> if a card is present; <code>false</code>
     * otherwise.
     *
     * @return <code>true</code> if a card is present; <code>false</code>
     *         otherwise.
     * @throws CardException if card presence information is not available.
     */
    boolean isCardPresent() throws Exception {
        return mTerminalService.isCardPresent();
    }

    /**
     * Performs a select command on the basic channel without an AID parameter.
     * <br>
     * The card manager will be selected.
     */
    public void select() {
        mSelectResponse = null;
        byte[] selectCommand = new byte[5];
        selectCommand[0] = 0x00;
        selectCommand[1] = (byte) 0xA4;
        selectCommand[2] = 0x04;
        selectCommand[3] = 0x00;
        selectCommand[4] = 0x00;
        try {
            mSelectResponse = transmit(
                    selectCommand, 2, 0x9000, 0xFFFF, "SELECT");
        } catch (Exception exp) {
            throw new NoSuchElementException(exp.getMessage());
        }
    }

    /**
     * Performs a select command on the basic channel.
     *
     * @param aid the aid which should be selected.
     */
    public void select(byte[] aid) {
        if (aid == null) {
            throw new NullPointerException("aid must not be null");
        }
        mSelectResponse = null;
        byte[] selectCommand = new byte[aid.length + 6];
        selectCommand[0] = 0x00;
        selectCommand[1] = (byte) 0xA4;
        selectCommand[2] = 0x04;
        selectCommand[3] = 0x00;
        selectCommand[4] = (byte) aid.length;
        System.arraycopy(aid, 0, selectCommand, 5, aid.length);
        try {
            // TODO: also accept 62XX and 63XX as valid SW
            mSelectResponse = transmit(
                    selectCommand, 2, 0x9000, 0xFFFF, "SELECT");
        } catch (Exception exp) {
            throw new NoSuchElementException(exp.getMessage());
        }
    }

    public synchronized Channel openBasicChannel(
            Session session,
            ISmartcardServiceCallback callback)
                    throws CardException {
        if (callback == null) {
            throw new NullPointerException("callback must not be null");
        }

        if (!mDefaultApplicationSelectedOnBasicChannel) {
            throw new CardException("default application is not selected");
        }
        if (getBasicChannel() != null) {
            throw new CardException("basic channel in use");
        }

        Channel basicChannel = createChannel(session, 0, callback);
        basicChannel.hasSelectedAid(false, null);
        registerChannel(basicChannel);
        return basicChannel;
    }

    public Channel openBasicChannel(
            Session session,
            byte[] aid,
            ISmartcardServiceCallback callback)
                    throws Exception {
        if (callback == null) {
            throw new NullPointerException("callback must not be null");
        }
        if (aid == null) {
            throw new NullPointerException("aid must not be null");
        }

        if (getBasicChannel() != null) {
            throw new CardException("basic channel in use");
        }

        select(aid);


        Channel basicChannel = createChannel(session, 0, callback);
        basicChannel.hasSelectedAid(true, aid);
        mDefaultApplicationSelectedOnBasicChannel = false;
        registerChannel(basicChannel);
        return basicChannel;
    }

    public synchronized Channel openLogicalChannel(
            Session session,
            ISmartcardServiceCallback callback)
                    throws Exception {
        if (callback == null) {
            throw new NullPointerException("callback must not be null");
        }

        int channelNumber = internalOpenLogicalChannel();


        Channel logicalChannel = createChannel(
                session, channelNumber, callback);
        logicalChannel.hasSelectedAid(false, null);
        registerChannel(logicalChannel);
        return logicalChannel;
    }

    public synchronized Channel openLogicalChannel(
            Session session,
            byte[] aid,
            ISmartcardServiceCallback callback)
                    throws Exception {
        if (callback == null) {
            throw new NullPointerException("callback must not be null");
        }
        if (aid == null) {
            throw new NullPointerException("aid must not be null");
        }

        int channelNumber = internalOpenLogicalChannel(aid);


        Channel logicalChannel = createChannel(
                session, channelNumber, callback);
        logicalChannel.hasSelectedAid(true, aid);
        registerChannel(logicalChannel);
        return logicalChannel;
    }

    public boolean isConnected() {
        return (mTerminalService != null);
    }

    /**
     * Protocol specific implementation of the transmit operation. This method
     * is synchronized in order to handle GET RESPONSE and command repetition
     * without interruption by other commands.
     *
     * @param cmd the command to be transmitted.
     * @return the response received.
     * @throws CardException if the transmit operation failed.
     */
    protected synchronized byte[] protocolTransmit(byte[] cmd)
            throws CardException {
        byte[] rsp = internalTransmit(cmd);

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
        return rsp;
    }

    /**
     * Creates a handle for the specified channel instances and adds the channel
     * instance to the channel list.
     *
     * @param channel
     * @return the channel handle.
     */
    private long registerChannel(Channel channel) {
        long hChannel = mRandom.nextInt();
        hChannel <<= 32;
        hChannel |= (((long) channel.hashCode()) & 0xFFFFFFFFL);

        channel.setHandle(hChannel);

        mChannels.put(hChannel, channel);

        return hChannel;
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
     * @throws CardException if the transmit operation or the minimum response
     *             length check or the status word check failed.
     */
    public synchronized byte[] transmit(
            byte[] cmd,
            int minRspLength,
            int swExpected,
            int swMask,
            String commandName)
                    throws CardException {
        byte[] rsp;
        try {
            rsp = protocolTransmit(cmd);
        } catch (Exception e) {
            if (commandName == null) {
                throw new CardException(e.getMessage());
            } else {
                throw new CardException(
                        Util.createMessage(commandName, "transmit failed"), e);
            }
        }
        if (minRspLength > 0) {
            if (rsp == null || rsp.length < minRspLength) {
                throw new CardException(
                        Util.createMessage(commandName, "response too small"));
            }
        }
        if (swMask != 0) {
            if (rsp == null || rsp.length < 2) {
                throw new CardException(
                        Util.createMessage(commandName, "SW1/2 not available"));
            }
            int sw1 = rsp[rsp.length - 2] & 0xFF;
            int sw2 = rsp[rsp.length - 1] & 0xFF;
            int sw = (sw1 << 8) | sw2;
            if ((sw & swMask) != (swExpected & swMask)) {
                throw new CardException(Util.createMessage(commandName, sw));
            }
        }
        return rsp;
    }

    public byte[] getSelectResponse() {
        return mSelectResponse;
    }

    public byte[] simIOExchange(int fileID, String filePath, byte[] cmd)
            throws Exception {
        SmartcardError error = new SmartcardError();
        try {
            return mTerminalService.simIOExchange(fileID, filePath, cmd, error);
        } catch (RemoteException e) {
            throw new Exception("SIM IO error!");
        }
    }

    public ChannelAccess setUpChannelAccess(
            PackageManager packageManager,
            byte[] aid,
            String packageName,
            ISmartcardServiceCallback callback) {
        if (mAccessControlEnforcer == null) {
            throw new AccessControlException(
                    "Access Control Enforcer not properly set up");
        }
        mAccessControlEnforcer.setPackageManager(packageManager);
        return mAccessControlEnforcer.setUpChannelAccess(
                aid, packageName, callback);
    }

    public synchronized boolean initializeAccessControl(
            boolean loadAtStartup,
            ISmartcardServiceCallback callback) {
        if (mAccessControlEnforcer == null) {
            mAccessControlEnforcer = new AccessControlEnforcer(this);
        }
        return mAccessControlEnforcer.initialize(loadAtStartup, callback);
    }

    public AccessControlEnforcer getAccessControlEnforcer() {
        return mAccessControlEnforcer;
    }

    public synchronized void resetAccessControl() {
        if (mAccessControlEnforcer != null) {
            mAccessControlEnforcer.reset();
        }
    }


    /**
     * Implementation of the SmartcardService Reader interface according to
     * OMAPI.
     */
    final class SmartcardServiceReader extends ISmartcardServiceReader.Stub {

        public byte[] getAtr(){
        	return Terminal.this.getAtr();
        }

        @Override
        public String getName(SmartcardError error) throws RemoteException {
            Util.clearError(error);
            return Terminal.this.getName();
        }

        @Override
        public boolean isSecureElementPresent(SmartcardError error)
                throws RemoteException {
            Util.clearError(error);
            try {
                return Terminal.this.isCardPresent();
            } catch (Exception e) {
                Util.setError(error, e);
            }
            return false;
        }

        @Override
        public ISmartcardServiceSession openSession(SmartcardError error)
                throws RemoteException {
            Util.clearError(error);
            try {
                if (!Terminal.this.isCardPresent()) {
                    Util.setError(
                            error,
                            new IOException("Secure Element is not presented.")
                            );
                    return null;
                }
            } catch (Exception e) {
                Util.setError(error, e);
                return null;
            }

            synchronized (mLock) {
                try {
                    initializeAccessControl(
                            false);
                } catch (Exception e) {
                    Util.setError(error, e);
                    // Reader.openSession() will throw an IOException when
                    // session is null
                    return null;
                }
                Session session = new Session(Terminal.this, mContext);
                mSessions.add(session);

                return session.new SmartcardServiceSession();
            }
        }

        @Override
        public void closeSessions(SmartcardError error) throws RemoteException {

            Util.clearError(error);
            try {
                Terminal.this.closeSessions(error);
            } catch (CardException e) {
                e.printStackTrace();
            }
        }

        /**
         * Closes the defined Session and all its allocated resources. <br>
         * After calling this method the Session can not be used for the
         * communication with the Secure Element any more.
         *
         * @param session the Session that should be closed
         * @throws RemoteException
         * @throws CardException
         * @throws NullPointerException if Session is null
         */
        synchronized void closeSession(Session session)
                throws RemoteException, CardException {
            if (session == null) {
                throw new NullPointerException("session is null");
            }
            if (!session.isClosed()) {
                SmartcardError error = new SmartcardError();
                session.closeChannels(error);
                error.throwException();
                session.setClosed();
            }
            mSessions.remove(session);
        }

        Terminal getTerminal() {
            return Terminal.this;
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
