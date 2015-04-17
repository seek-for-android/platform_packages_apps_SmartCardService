package org.simalliance.openmobileapi.service;

import android.content.Context;
import android.os.Binder;
import android.os.RemoteException;
import android.util.Log;

import org.simalliance.openmobileapi.service.security.ChannelAccess;


import java.io.PrintWriter;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Random;

/**
 * The smartcard service interface implementation.
 */
public class Session {

    private final Terminal mReader;
    private Context mContext;
    private boolean mIsClosed;
    /**
     * List of open channels in use by this client.
     */
    private final Map<Long, Channel> mChannels = new HashMap<>();
    /**
     * Random number generator used for handle creation.
     */
    private Random mRandom = new Random();
    private final Object mLock = new Object();

    public Session(Terminal reader, Context context) {
        mReader = reader;
        mIsClosed = false;
        mContext = context;
    }

    public SmartcardServiceSession getBinder() {
        return new SmartcardServiceSession();
    }

    public Terminal getReader() {
        return mReader;
    }

    public byte[] getAtr() throws RemoteException {
        return mReader.getAtr();
    }

    public synchronized void close() {
        if (isClosed()) {
            return;
        }
        closeChannels();
        mIsClosed = true;
        mReader.sessionClosed(this);
    }

    public void closeChannels() {
        synchronized (mLock) {
            Collection<Channel> col = mChannels.values();
            Channel[] channelList = col.toArray(new Channel[col.size()]);
            for (Channel channel : channelList) {
                if (channel != null && !channel.isClosed()) {
                    try {
                        channel.close();
                        removeChannel(channel);
                    } catch (Exception ignore) {
                        Log.e(SmartcardService.LOG_TAG,
                                "ServiceSession channel - close Exception: " + ignore.getMessage(),
                                ignore);
                    }
                }
            }
            mChannels.clear();
        }
    }

    public boolean isClosed() {
        return mIsClosed;
    }

    public ISmartcardServiceChannel openBasicChannel(
            byte[] aid,
            ISmartcardServiceCallback callback) throws Exception {

        if (isClosed()) {
            throw new IllegalStateException("Session is closed");
        }
        if (callback == null) {
            throw new IllegalStateException("Callback must not be null");
        }
        if (mReader == null) {
            throw new IllegalStateException("Reader must not be null");
        }

        boolean noAid = false;
        if (aid == null || aid.length == 0) {
            aid = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 };
            noAid = true;
        }

        if (aid.length < 5 || aid.length > 16) {
            throw new IllegalArgumentException("AID out of range");
        }

        String packageName = Util.getPackageNameFromCallingUid(
                mContext,
                Binder.getCallingUid());
        Log.v(SmartcardService.LOG_TAG, "Enable access control on basic channel for "
                + packageName);
        ChannelAccess channelAccess = mReader.
                setUpChannelAccess(mContext.getPackageManager(), aid, packageName);
        Log.v(SmartcardService.LOG_TAG, "Access control successfully enabled.");

        channelAccess.setCallingPid(Binder.getCallingPid());

        Log.v(SmartcardService.LOG_TAG, "OpenBasicChannel(AID)");
        if (mReader.getBasicChannel() != null) {
            return null;
        }
        Channel channel;
        if (noAid) {
            if (!mReader.getDefaultApplicationSelectedOnBasicChannel()) {
                throw new IllegalStateException("default application is not selected");
            }
            channel = new Channel(this, 0, null, callback);
            channel.hasSelectedAid(false, null);

        } else {
            byte[] selectCommand = new byte[aid.length + 6];
            selectCommand[0] = 0x00;
            selectCommand[1] = (byte) 0xA4;
            selectCommand[2] = 0x04;
            selectCommand[3] = 0x00;
            selectCommand[4] = (byte) aid.length;
            System.arraycopy(aid, 0, selectCommand, 5, aid.length);
            byte[] selectResponse;
            try {
                // TODO: also accept 62XX and 63XX as valid SW
                selectResponse = transmit(
                        selectCommand, 2, 0x9000, 0xFFFF, "SELECT ON BASIC CHANNEL");
            } catch (Exception exp) {
                throw new NoSuchElementException(exp.getMessage());
            }

            channel = new Channel(this, 0, selectResponse, callback);
            channel.hasSelectedAid(true, aid);
        }

        channel.setChannelAccess(channelAccess);

        Log.v(SmartcardService.LOG_TAG, "Open basic channel success. Channel: " + channel.getChannelNumber());

        registerChannel(channel);
        return channel.getBinder();
    }

    public ISmartcardServiceChannel openLogicalChannel(
            byte[] aid,
            ISmartcardServiceCallback callback) throws Exception {

        if (isClosed()) {
            throw new IllegalStateException("Session is closed");
        }
        if (callback == null) {
            throw new IllegalStateException("Callback must not be null");
        }
        if (mReader == null) {
            throw new IllegalStateException("Reader must not be null");
        }

        boolean noAid = false;
        if (aid == null || aid.length == 0) {
            aid = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 };
            noAid = true;
        }

        if (aid.length < 5 || aid.length > 16) {
            throw new IllegalArgumentException("AID out of range");
        }

        String packageName = Util.getPackageNameFromCallingUid(
                mContext,
                Binder.getCallingUid());
        Log.v(SmartcardService.LOG_TAG, "Enable access control on logical channel for "
                + packageName);
        ChannelAccess channelAccess = mReader.
                setUpChannelAccess(mContext.getPackageManager(), aid, packageName);
        Log.v(SmartcardService.LOG_TAG, "Access control successfully enabled.");
        channelAccess.setCallingPid(Binder.getCallingPid());


        Log.v(SmartcardService.LOG_TAG, "OpenLogicalChannel");
        if (noAid) {
            aid = null;
        }

        OpenLogicalChannelResponse rsp;
        synchronized (this) {
            rsp = mReader.internalOpenLogicalChannel(aid);
        }

        if (rsp == null) {
            return null;
        }

        Channel channel = new Channel(this, rsp.getChannel(), rsp.getSelectResponse(), callback);
        channel.hasSelectedAid(true, aid);
        channel.setChannelAccess(channelAccess);

        Log.v(SmartcardService.LOG_TAG, "Open logical channel successfull. Channel: " + channel.getChannelNumber());

        registerChannel(channel);
        return channel.getBinder();
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
    public byte[] transmit(
            byte[] cmd,
            int minRspLength,
            int swExpected,
            int swMask,
            String commandName) throws Exception {
        return mReader.transmit(cmd, minRspLength, swExpected, swMask, commandName);
    }

    public void closeChannel(int channelNumber) throws Exception {
        mReader.internalCloseLogicalChannel(channelNumber);
    }

    public Channel getBasicChannel() {
        for (Channel channel : mChannels.values()) {
            if (channel.getChannelNumber() == 0) {
                return channel;
            }
        }
        return null;
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
     * Closes the specified channel. <br>
     * After calling this method the session can not be used for the
     * communication with the secure element any more.
     *
     * @param channel the channel handle obtained by an open channel
     *        command.
     */
    private void removeChannel(Channel channel) {
        if (channel == null) {
            return;
        }
        mChannels.remove(channel.getHandle());
    }

    public void dump(PrintWriter writer, String prefix) {
        for (Channel channel : mChannels.values()) {
            writer.println(prefix + "  channel " + channel.getChannelNumber()
                    + ": ");
            writer.println(prefix + "    package      : "
                    + channel.getChannelAccess().getPackageName());
            writer.println(prefix + "    pid          : "
                    + channel.getChannelAccess().getCallingPid());
            writer.println(prefix + "    basic channel: "
                    + channel.isBasicChannel());
        }
    }

    private class SmartcardServiceSession extends ISmartcardServiceSession.Stub {

        @Override
        public byte[] getAtr() throws RemoteException {
            return Session.this.getAtr();
        }

        @Override
        public void close(SmartcardError error) throws RemoteException {
            try {
                Session.this.close();
            } catch (Exception e) {
                Log.e(SmartcardService.LOG_TAG, "Error during close()", e);
                error.set(e);
            }
        }

        @Override
        public void closeChannels(SmartcardError error) throws RemoteException {
            try {
                Session.this.closeChannels();
            } catch (Exception e) {
                Log.e(SmartcardService.LOG_TAG, "Error during closeChannel()", e);
                error.set(e);
            }
        }

        @Override
        public boolean isClosed() throws RemoteException {
            return Session.this.isClosed();
        }

        @Override
        public ISmartcardServiceChannel openBasicChannel(
                byte[] aid,
                ISmartcardServiceCallback callback,
                SmartcardError error) throws RemoteException {
            try {
                return Session.this.openBasicChannel(aid, callback);
            } catch (Exception e) {
                Log.e(SmartcardService.LOG_TAG, "Error during openBasicChannel()", e);
                error.set(e);
                return null;
            }
        }

        @Override
        public ISmartcardServiceChannel openLogicalChannel(
                byte[] aid,
                ISmartcardServiceCallback callback,
                SmartcardError error) throws RemoteException {
            try {
                return Session.this.openLogicalChannel(aid, callback);
            } catch (Exception e) {
                Log.e(SmartcardService.LOG_TAG, "Error during openLogicalChannel()", e);
                error.set(e);
                return null;
            }
        }
    }
}
