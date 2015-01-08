package org.simalliance.openmobileapi.service;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Created by sevilser on 23/12/14.
 */
public class OpenLogicalChannelResponse implements Parcelable {

    private int mChannelNumber;
    private byte[] mSelectResponse;

    public static final Parcelable.Creator<OpenLogicalChannelResponse> CREATOR = new Parcelable.Creator<OpenLogicalChannelResponse>() {
        public OpenLogicalChannelResponse createFromParcel(Parcel in) {
            return new OpenLogicalChannelResponse(in);
        }

        public OpenLogicalChannelResponse[] newArray(int size) {
            return new OpenLogicalChannelResponse[size];
        }
    };

    public OpenLogicalChannelResponse(int channelNumber, byte[] selectResponse) {
        mChannelNumber = channelNumber;
        mSelectResponse = selectResponse;
    }

    private OpenLogicalChannelResponse(Parcel in) {
        mChannelNumber = in.readInt();
        in.readByteArray(mSelectResponse);
    }

    public int getChannel() {
        return mChannelNumber;
    }

    public byte[] getSelectResponse() {
        return mSelectResponse;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel out, int flags) {
        out.writeInt(mChannelNumber);
        out.writeByteArray(mSelectResponse);
    }
}
