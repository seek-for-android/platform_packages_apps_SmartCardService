package org.simalliance.openmobileapi.service;

import android.content.Context;
import android.os.Binder;
import android.os.RemoteException;
import android.util.Log;

import org.simalliance.openmobileapi.service.security.AccessControlEnforcer;
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
    /** List of open channels in use of by this client. */
    private final Map<Long, Channel> mChannels = new HashMap<Long, Channel>();

    public static final String _TAG = "SmartcardServiceSession";

    private final Object mLock = new Object();

    private boolean mIsClosed;

    /** Random number generator used for handle creation. */
    static Random mRandom = new Random();

    private byte[] mAtr;

    private Context mContext;
    public Session(Terminal reader, Context context) {
        mReader = reader;
        mAtr = mReader.getAtr();
        mIsClosed = false;
        mContext = context;
    }


    void setClosed() {
        mIsClosed = true;
    }

    /**
     * Closes the specified channel. <br>
     * After calling this method the session can not be used for the
     * communication with the secure element any more.
     *
     * @param channel the channel handle obtained by an open channel
     *        command.
     */
    void removeChannel(Channel channel) {
        if (channel == null) {
            return;
        }
        mChannels.remove(channel);
    }

    public ISmartcardServiceReader getReader() throws RemoteException {
        return mReader.new SmartcardServiceReader();
    }

    public byte[] getAtr() throws RemoteException {
        return mAtr;
    }

    public void close(SmartcardError error) {
        Util.clearError(error);
        if (mReader == null) {
            return;
        }
        mReader.closeSession(this, error);
    }

    public void closeChannels(SmartcardError error) {
        synchronized (mLock) {
            Collection<Channel> col = mChannels.values();
            Channel[] channelList = col.toArray(new Channel[col.size()]);
            for (Channel channel : channelList) {
                if (channel != null && !channel.isClosed()) {
                    try {
                        channel.close(error);
                        mIsClosed = true;
                    } catch (Exception ignore) {
                        Log.e(_TAG, "ServiceSession channel - close"
                                + " Exception " + ignore.getMessage());
                    }
                }
            }
            mChannels.clear();
        }
    }

    public boolean isClosed() {

        return mIsClosed;
    }

    public ISmartcardServiceChannel openBasicChannel(byte[] aid,
                                                        ISmartcardServiceCallback callback, SmartcardError error)
            throws RemoteException {
        Util.clearError(error);
        if (isClosed()) {
            Util.setError(error, IllegalStateException.class,
                    "session is closed");
            return null;
        }
        if (callback == null) {
            Util.setError(error, IllegalStateException.class,
                    "callback must not be null");
            return null;
        }
        if (mReader == null) {
            Util.setError(error, IllegalStateException.class,
                    "reader must not be null");
            return null;
        }

        try {
            boolean noAid = false;
            if (aid == null || aid.length == 0) {
                aid = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 };
                noAid = true;
            }

            if (aid.length < 5 || aid.length > 16) {
                Util.setError(error, IllegalArgumentException.class,
                        "AID out of range");
                return null;
            }


            String packageName = Util.getPackageNameFromCallingUid(
                    mContext,
                    Binder.getCallingUid());
            Log.v(_TAG, "Enable access control on basic channel for "
                    + packageName);
            ChannelAccess channelAccess = mReader.
                    setUpChannelAccess(mContext.getPackageManager(), aid,
                            packageName, callback);
            Log.v(_TAG, "Access control successfully enabled.");

            channelAccess.setCallingPid(Binder.getCallingPid());



            Log.v(_TAG, "OpenBasicChannel(AID)");
            if (mReader.getBasicChannel() != null) {
                throw new IllegalStateException("basic channel in use");
            }
            Channel channel;
            if (noAid) {
                if (!mReader.getDefaultApplicationSelectedOnBasicChannel()) {
                    throw new IllegalStateException("default application is not selected");
                }
                channel = new Channel(this, 0, null, callback);
                channel.hasSelectedAid(false, null);

            } else {
                byte[] selectResponse = null;
                byte[] selectCommand = new byte[aid.length + 6];
                selectCommand[0] = 0x00;
                selectCommand[1] = (byte) 0xA4;
                selectCommand[2] = 0x04;
                selectCommand[3] = 0x00;
                selectCommand[4] = (byte) aid.length;
                System.arraycopy(aid, 0, selectCommand, 5, aid.length);
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

            Log.v(_TAG,
                    "Open basic channel success. Channel: "
                            + channel.getChannelNumber());

            Channel.SmartcardServiceChannel basicChannel
                    = channel.new SmartcardServiceChannel(this);
            registerChannel(channel);
            return basicChannel;

        } catch (Exception e) {
            Util.setError(error, e);
            Log.v(_TAG, "OpenBasicChannel Exception: " + e.getMessage());
            return null;
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
    public byte[] transmit(
            byte[] cmd,
            int minRspLength,
            int swExpected,
            int swMask,
            String commandName) {
        return mReader.transmit(cmd, minRspLength, swExpected, swMask, commandName);
    }
    public ISmartcardServiceChannel openLogicalChannel(byte[] aid,
                                                       ISmartcardServiceCallback callback, SmartcardError error)
            throws RemoteException {
        Util.clearError(error);

        if (isClosed()) {
            Util.setError(error, IllegalStateException.class,
                    "session is closed");
            return null;
        }

        if (callback == null) {
            Util.setError(error, IllegalStateException.class,
                    "callback must not be null");
            return null;
        }
        if (mReader == null) {
            Util.setError(error, IllegalStateException.class,
                    "reader must not be null");
            return null;
        }

        try {
            boolean noAid = false;
            if (aid == null || aid.length == 0) {
                aid = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 };
                noAid = true;
            }

            if (aid.length < 5 || aid.length > 16) {
                Util.setError(error, IllegalArgumentException.class,
                        "AID out of range");
                return null;
            }


            String packageName = Util.getPackageNameFromCallingUid(
                    mContext,
                    Binder.getCallingUid());
            Log.v(_TAG, "Enable access control on logical channel for "
                    + packageName);
            ChannelAccess channelAccess = mReader.
                    setUpChannelAccess(mContext.getPackageManager(), aid,
                            packageName, callback);
            Log.v(_TAG, "Access control successfully enabled.");
            channelAccess.setCallingPid(Binder.getCallingPid());


            Log.v(_TAG, "OpenLogicalChannel");
            Channel channel;
            OpenLogicalChannelResponse rsp;
            if (noAid) {
                aid = null;
            }
            synchronized (this) {
                rsp = mReader.internalOpenLogicalChannel(aid);
                channel = new Channel(this, rsp.getChannel(), rsp.getSelectResponse(), callback);
                channel.hasSelectedAid(true, aid);
            }

            channel.setChannelAccess(channelAccess);

            Log.v(_TAG, "Open logical channel successfull. Channel: "
                    + channel.getChannelNumber());
            Channel.SmartcardServiceChannel logicalChannel
                    = channel.new SmartcardServiceChannel(this);
            registerChannel(channel);
            return logicalChannel;
        } catch (Exception e) {
            Util.setError(error, e);
            Log.v(_TAG, "OpenLogicalChannel Exception: " + e.getMessage());
            return null;
        }
    }

    public void closeChannel(int channelNumber) {
        mReader.internalCloseLogicalChannel(channelNumber);
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

    public Channel getBasicChannel() {
        for (Channel channel : mChannels.values()) {
            if (channel.getChannelNumber() == 0) {
                return channel;
            }
        }
        return null;
    }

    public AccessControlEnforcer getAccessControlEnforcer() {
        return mReader.getAccessControlEnforcer();
    }

    public String getReaderName() {
        return mReader.getName();
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

    final class SmartcardServiceSession extends ISmartcardServiceSession.Stub {
        @Override
        public ISmartcardServiceReader getReader() throws RemoteException {
            return mReader.new SmartcardServiceReader();
        }

        @Override
        public byte[] getAtr() throws RemoteException {
            return mAtr;
        }

        @Override
        public void close(SmartcardError error) throws RemoteException {
            Util.clearError(error);
            Session.this.close(error);
            if(error.createException() != null) {
                error.throwException();
            }
        }

        @Override
        public void closeChannels(SmartcardError error) throws RemoteException {
            Util.clearError(error);
            Session.this.closeChannels(error);
            if(error.createException() != null) {
                error.throwException();
            }
        }

        @Override
        public boolean isClosed() throws RemoteException {

            return mIsClosed;
        }

        @Override
        public ISmartcardServiceChannel openBasicChannel(
                ISmartcardServiceCallback callback, SmartcardError error)
                throws RemoteException {
            Util.clearError(error);
            return Session.this.openBasicChannel(null, callback, error);
        }

        @Override
        public ISmartcardServiceChannel openBasicChannelAid(byte[] aid,
                                                            ISmartcardServiceCallback callback, SmartcardError error)
                throws RemoteException {
            Util.clearError(error);
            return Session.this.openBasicChannel(aid, callback, error);
        }

        @Override
        public ISmartcardServiceChannel openLogicalChannel(byte[] aid,
                                                           ISmartcardServiceCallback callback, SmartcardError error)
                throws RemoteException {
            Util.clearError(error);
            return Session.this.openLogicalChannel(aid, callback, error);
        }
    }
}
