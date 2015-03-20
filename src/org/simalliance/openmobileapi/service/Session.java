package org.simalliance.openmobileapi.service;

import android.content.Context;
import android.os.Binder;
import android.os.RemoteException;
import android.util.Log;

import org.simalliance.openmobileapi.service.security.ChannelAccess;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * The smartcard service interface implementation.
 */
public class Session {

    private final Terminal.SmartcardServiceReader mReader;
    /** List of open channels in use of by this client. */
    private final Set<Channel> mChannels = new HashSet<Channel>();

    public static final String _TAG = "SmartcardServiceSession";

    private final Object mLock = new Object();

    private boolean mIsClosed;

    private byte[] mAtr;

    private Context mContext;
    public Session(Terminal.SmartcardServiceReader reader, Context context) {
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
        return mReader;
    }

    public byte[] getAtr() throws RemoteException {
        return mAtr;
    }

    public void close(SmartcardError error) throws RemoteException {
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

    public void closeChannels(SmartcardError error) throws RemoteException {
        synchronized (mLock) {

            Iterator<Channel> iter = mChannels.iterator();
            try {
                while (iter.hasNext()) {
                    Channel channel = iter.next();
                    if (channel != null && !channel.isClosed()) {
                        try {
                            channel.close();
                            // close changes indirectly mChannels, so we
                            // need a new iterator.
                            iter = mChannels.iterator();
                        } catch (Exception ignore) {
                            Log.e(_TAG, "ServiceSession channel - close"
                                    + " Exception " + ignore.getMessage());
                        }
                    }
                }
                mChannels.clear();
            } catch (Exception e) {
                Log.e(_TAG,
                        "ServiceSession closeChannels Exception "
                                + e.getMessage());
            }
        }
    }

    public boolean isClosed() throws RemoteException {

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
            ChannelAccess channelAccess = mReader.getTerminal()
                    .setUpChannelAccess(mContext.getPackageManager(), aid,
                            packageName, callback);
            Log.v(_TAG, "Access control successfully enabled.");

            channelAccess.setCallingPid(Binder.getCallingPid());



            Log.v(_TAG, "OpenBasicChannel(AID)");
            Channel channel;
            if (noAid) {
                channel = mReader.getTerminal().openBasicChannel(this,
                        callback);
            } else {
                channel = mReader.getTerminal().openBasicChannel(this, aid,
                        callback);
            }

            channel.setChannelAccess(channelAccess);

            Log.v(_TAG,
                    "Open basic channel success. Channel: "
                            + channel.getChannelNumber());

            Channel.SmartcardServiceChannel basicChannel
                    = channel.new SmartcardServiceChannel(this);
            mChannels.add(channel);
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
            ChannelAccess channelAccess = mReader.getTerminal()
                    .setUpChannelAccess(mContext.getPackageManager(), aid,
                            packageName, callback);
            Log.v(_TAG, "Access control successfully enabled.");
            channelAccess.setCallingPid(Binder.getCallingPid());


            Log.v(_TAG, "OpenLogicalChannel");
            Channel channel;
            if (noAid) {
                channel = mReader.getTerminal().openLogicalChannel(this,
                        callback);
            } else {
                channel = mReader.getTerminal().openLogicalChannel(this,
                        aid, callback);
            }

            channel.setChannelAccess(channelAccess);

            Log.v(_TAG, "Open logical channel successfull. Channel: "
                    + channel.getChannelNumber());
            Channel.SmartcardServiceChannel logicalChannel
                    = channel.new SmartcardServiceChannel(this);
            mChannels.add(channel);
            return logicalChannel;
        } catch (Exception e) {
            Util.setError(error, e);
            Log.v(_TAG, "OpenLogicalChannel Exception: " + e.getMessage());
            return null;
        }
    }

    final class SmartcardServiceSession extends ISmartcardServiceSession.Stub {
        @Override
        public ISmartcardServiceReader getReader() throws RemoteException {
            return mReader;
        }

        @Override
        public byte[] getAtr() throws RemoteException {
            return mAtr;
        }

        @Override
        public void close(SmartcardError error) throws RemoteException {
            Util.clearError(error);
            try {
                Session.this.close(error);
            } catch (Exception e) {
                Util.setError(error, e);
            }
        }

        @Override
        public void closeChannels(SmartcardError error) throws RemoteException {
            Session.this.closeChannels(error);
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
