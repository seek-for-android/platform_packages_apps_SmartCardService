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

import org.simalliance.openmobileapi.service.ISmartcardServiceChannel;
import org.simalliance.openmobileapi.service.SmartcardError;

import android.os.RemoteException;
import android.util.Log;

/**
 * Instances of this class represent an ISO7816-4 channel opened to a secure
 * element. It can be either a logical channel or the default channel. They can
 * be used to send APDUs to the secure element. Channels are opened by calling
 * the Session.openBasicChannel(byte[]) or Session.openLogicalChannel(byte[])
 * methods.
 * 
 * @see <a href="http://simalliance.org">SIMalliance Open Mobile API  v2.02</a>
 */
public class Channel {

    private Session mSession;

    private final ISmartcardServiceChannel mChannel;
    private final SEService mService;
    
    private final Object mLock = new Object();

    Channel(SEService service, Session session, ISmartcardServiceChannel channel) {
    	mService = service;
        mSession = session;
        mChannel = channel;
    }

    /**
     * Closes this channel to the Secure Element. If the method is called when
     * the channel is already closed, this method will be ignored. The close()
     * method shall wait for completion of any pending transmit(byte[] command)
     * before closing the channel.
     */
    public void close() {
        if (mService == null || !mService.isConnected()) {
            throw new IllegalStateException("service not connected to system");
        }
        if (mChannel == null) {
            throw new IllegalStateException("channel must not be null");
        }
        if (!isClosed()) {
            synchronized (mLock) {
                SmartcardError error = new SmartcardError();
                try {
                    mChannel.close(error);
                } catch (RemoteException e) {
                    throw new IllegalStateException(e.getMessage());
                }
                SEService.checkForException(error);
            }
        }
    }

    /**
     * Tells if this channel is closed.
     * 
     * @return <code>true</code> if the channel is closed, <code>false</code> otherwise.
     */
    public boolean isClosed() {
        if (mService == null || mService.isConnected() == false) {
            throw new IllegalStateException("service not connected to system");
        }
        if (mChannel == null) {
            throw new IllegalStateException("channel must not be null");
        }
        try {
			return mChannel.isClosed();
        } catch (RemoteException e) {
            throw new IllegalStateException(e.getMessage());
        }
    }

    /**
     * Returns a boolean telling if this channel is the basic channel.
     * 
     * @return <code>true</code> if this channel is a basic channel. <code>false</code> if
     *         this channel is a logical channel.
     */
    public boolean isBasicChannel() {
        if (mService == null || mService.isConnected() == false) {
            throw new IllegalStateException("service not connected to system");
        }
        if (mChannel == null) {
            throw new IllegalStateException("channel must not be null");
        }
        try {
			return mChannel.isBasicChannel();
		} catch (RemoteException e) {
			throw new IllegalStateException(e.getMessage());
		}
    }

    /**
     * Transmit an APDU command (as per ISO7816-4) to the secure element and
     * wait for the response. The underlying layers might generate as much TPDUs
     * as necessary to transport this APDU. The transport part is invisible from
     * the application. <br>
     * The system ensures the synchronization between all the concurrent calls
     * to this method, and that only one APDU will be sent at a time,
     * irrespective of the number of TPDUs that might be required to transport
     * it to the SE. <br>
     * The channel information in the class byte in the APDU will be completely
     * ignored. The underlying system will add any required information to
     * ensure the APDU is transported on this channel. There are restrictions on
     * the set of commands that can be sent: <br>
     * 
     * <ul> 
     * <li>MANAGE_CHANNEL commands are not allowed.</li> 
     * <li>SELECT by DF Name (p1=04) are not allowed.</li>
     * <li>CLA bytes with channel numbers are de-masked.</li> 
     * </ul>
     * 
     * @param command the APDU command to be transmitted, as a byte array.
     * 
     * @return the response received, as a byte array.
     * 
     * @throws IOException if there is a communication problem to the reader or the Secure Element.
     * @throws IllegalStateException if the channel is used after being closed.
     * @throws IllegalArgumentException if the command byte array is less than 4 bytes long.
     * @throws IllegalArgumentException if the length of the APDU is not coherent with the length of the command byte array.
     * @throws SecurityException if the command is filtered by the security
     *             policy
     */
    public byte[] transmit(byte[] command) throws IOException {
        if (mService == null || mService.isConnected() == false) {
            throw new IllegalStateException("service not connected to system");
        }
        if (mChannel == null) {
            throw new IllegalStateException("channel must not be null");
        }

        // if channel is closed is checked within service transmit call.

        byte[] response;
        synchronized( mLock ) {
            SmartcardError error = new SmartcardError();
            try {
                response = mChannel.transmit(command, error);
            } catch (RemoteException e1) {
                throw new IllegalStateException(e1.getMessage());
            } catch (Exception e) {
                throw new IOException(e.getMessage());
            }
            SEService.checkForException(error);
        }
        return response;
    }
    
    /**
     * Get the session that has opened this channel.
     * 
     * @return the session object this channel is bound to.
     */
    public Session getSession() {
        return mSession;
    }    
    
    /**
     * Returns the data as received from the application select command inclusively the status word.
     * The returned byte array contains the data bytes in the following order:
     * [&lt;first data byte&gt;, ..., &lt;last data byte&gt;, &lt;sw1&gt;, &lt;sw2&gt;]
     * @return The data as returned by the application select command inclusively the status word.
     * Only the status word if the application select command has no returned data.
     * Returns null if an application select command has not been performed or the selection response can not
     * be retrieved by the reader implementation.
     */
    public byte[] getSelectResponse()
    {
       	if (mService == null || mService.isConnected() == false) {
            throw new IllegalStateException("service not connected to system");
        }
        if (mChannel == null) {
            throw new IllegalStateException("channel must not be null");
        }
        try {
			if (mChannel.isClosed()) {
			    throw new IllegalStateException("channel is closed");
			}
		} catch (RemoteException e1) {
		    throw new IllegalStateException(e1.getMessage());
		}

        byte[] response;
        try {
            response = mChannel.getSelectResponse();
        } catch (RemoteException e) {
		    throw new IllegalStateException(e.getMessage());
        }
        
        if(response != null && response.length == 0)
    		response = null;
    	return response;
    }
    
    /**
     * Performs a selection of the next Applet on this channel that matches to the partial AID specified   
     * in the openBasicChannel(byte[] aid) or openLogicalChannel(byte[] aid) method.  
     * This mechanism can be used by a device application to iterate through all Applets 
     * matching to the same partial AID. 
     * If selectNext() returns true a new Applet was successfully selected on this channel. 
     * If no further Applet exists with matches to the partial AID this method returns false
     * and the already selected Applet stays selected.
     *
     * @return <code>true</code> if new Applet was successfully selected.
               <code>false</code> if no further Applet exists which matches the partial AID.
     *
     * @throws IOException if there is a communication problem to the reader or the Secure Element.
     * @throws IllegalStateException if the channel is used after being closed or it is not connected.
     * @throws SecurityException if the command is filtered by the security policy
     * @throws UnsupportedOperationException if selectNext is not supported by Secure Element.
     */
    public boolean selectNext() throws IOException {
       	if (mService == null || mService.isConnected() == false) {
            throw new IllegalStateException("service not connected to system");
        }
        if (mChannel == null) {
            throw new IllegalStateException("channel must not be null");
        }
        try {
			if (mChannel.isClosed()) {
			    throw new IllegalStateException("channel is closed");
			}
		} catch (RemoteException e1) {
		    throw new IllegalStateException(e1.getMessage());
		}
        
        boolean response = false;
        synchronized( mLock ) {
	        SmartcardError error = new SmartcardError();
	        try {
	            response = mChannel.selectNext(error);
            } catch (RemoteException e1) {
                throw new IllegalStateException(e1.getMessage());
	        } catch (Exception e) {
	            throw new IOException(e.getMessage());
	        }
	        SEService.checkForException(error);
        }
        return response;
    	
    }
    

    // ******************************************************************
    // package private methods
    // ******************************************************************
}
