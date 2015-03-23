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
        try {
            mReader.closeSession(this);
        } catch (CardException e) {
            Util.setError(error, e);
        }
    }

    public void closeChannels() {
        synchronized (mLock) {
            Collection<Channel> col = mChannels.values();
            Channel[] channelList = col.toArray(new Channel[col.size()]);
            for (Channel channel : channelList) {
                if (channel != null && !channel.isClosed()) {
                    try {
                        channel.close();
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

    public ISmartcardServiceChannel openBasicChannel(
            ISmartcardServiceCallback callback, SmartcardError error)
            throws RemoteException {
        return openBasicChannelAid(null, callback, error);
    }

    public ISmartcardServiceChannel openBasicChannelAid(byte[] aid,
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

            Channel channel;
            if (noAid) {
                channel = mReader.openBasicChannel(this, null,
                        callback);
            } else {
                channel = mReader.openBasicChannel(this, aid,
                        callback);
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
            if (noAid) {
                channel = mReader.openLogicalChannel(this, null,
                        callback);
            } else {
                channel = mReader.openLogicalChannel(this,
                        aid, callback);
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

    public void dump(PrintWriter writer, String prefix) {
        for (Channel channel : mChannels.values()) {
            writer.println(prefix + "  channel " + channel.getChannelNumber()
                    + ": ");
            writer.println(prefix + "    package      : "
                    + channel.getChannelAccess().getPackageName());
            writer.println(prefix + "    pid          : "
                    + channel.getChannelAccess().getCallingPid());
            writer.println(prefix + "    aid selected : "
                    + channel.hasSelectedAid());
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
        }

        @Override
        public void closeChannels(SmartcardError error) throws RemoteException {
            Session.this.closeChannels();
        }

        @Override
        public boolean isClosed() throws RemoteException {

            return mIsClosed;
        }

        @Override
        public ISmartcardServiceChannel openBasicChannel(
                ISmartcardServiceCallback callback, SmartcardError error)
                throws RemoteException {
            return Session.this.openBasicChannel(callback, error);
        }

        @Override
        public ISmartcardServiceChannel openBasicChannelAid(byte[] aid,
                                                            ISmartcardServiceCallback callback, SmartcardError error)
                throws RemoteException {
            Util.clearError(error);
            return Session.this.openBasicChannelAid(aid, callback, error);
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
