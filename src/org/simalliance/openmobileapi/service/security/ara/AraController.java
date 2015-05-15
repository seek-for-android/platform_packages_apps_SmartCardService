/*
 * Copyright 2012 Giesecke & Devrient GmbH.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.simalliance.openmobileapi.service.security.ara;

import android.util.Log;

import java.util.ArrayList;
import java.util.NoSuchElementException;
import java.util.MissingResourceException;

import org.simalliance.openmobileapi.service.SmartcardService;
import org.simalliance.openmobileapi.service.Channel;
import org.simalliance.openmobileapi.service.ISmartcardServiceCallback;
import org.simalliance.openmobileapi.service.OpenLogicalChannelResponse;
import org.simalliance.openmobileapi.service.Terminal;
import org.simalliance.openmobileapi.service.security.AccessControlEnforcer;
import org.simalliance.openmobileapi.service.security.AccessRuleCache;
import org.simalliance.openmobileapi.service.security.ChannelAccess;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.BerTlv;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.ParserException;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.REF_AR_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Response_ALL_AR_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Response_DO_Factory;

public class AraController {

    private AccessControlEnforcer mMaster = null;
    private AccessRuleCache mAccessRuleCache = null;

    private Terminal mTerminal = null;
    private AccessRuleApplet mApplet = null;
    
    
    private boolean mNoSuchElement = false;

    private String ACCESS_CONTROL_ENFORCER_TAG = "ACE ARA";

    public static final byte[] ARA_M_AID = new byte[] {
            (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x51, (byte)0x41, (byte)0x43, (byte)0x4C,
            (byte)0x00
    };

    public AraController(AccessControlEnforcer master ) {
        mMaster = master;
        mAccessRuleCache = mMaster.getAccessRuleCache();
        mTerminal = mMaster.getTerminal();

    }

    public boolean isNoSuchElement(){
        return mNoSuchElement;
    }

    public static byte[] getAraMAid() {
        return ARA_M_AID;
    }

    public synchronized boolean initialize(
            boolean loadAtStartup,
            ISmartcardServiceCallback callback) {

        Channel channel;
        try {
            channel = this.handleOpenChannel(callback);
        } catch( MissingResourceException e ){
            channel = null;
        }

        if( channel == null ){
            throw new SecurityException("could not open channel");
        }

        try {
            // set new applet handler since a new channel is used.
            mApplet = new AccessRuleApplet(mTerminal, channel);
            byte[] tag = mApplet.readRefreshTag();
            // if refresh tag is equal to the previous one it is not
            // neccessary to read all rules again.
            if( mAccessRuleCache.isRefreshTagEqual(tag)) {
                Log.d(ACCESS_CONTROL_ENFORCER_TAG, "Refresh tag has not changed. Using access rules from cache.");
                return false;
            }
            Log.d(ACCESS_CONTROL_ENFORCER_TAG, "Refresh tag has changed.");
            // set new refresh tag and empty cache.
            mAccessRuleCache.setRefreshTag(tag);
            mAccessRuleCache.clearCache();

            if( loadAtStartup ) {
                // Read content from ARA
                Log.d(ACCESS_CONTROL_ENFORCER_TAG, "Read ARs from ARA");
                this.readAllAccessRules();
            }
        } catch (Exception e) {
            Log.d(ACCESS_CONTROL_ENFORCER_TAG, "ARA error: " + e.getLocalizedMessage());
            throw new SecurityException(e.getLocalizedMessage());
        } finally {
            closeChannel(channel);
        }
        return true;
    }

    private Channel handleOpenChannel( ISmartcardServiceCallback callback ){
        Channel channel;
        String reason;

        try {
            channel = openChannel(mTerminal, getAraMAid(), callback);
        } catch (Exception e) {
            String msg = e.toString();
            msg = " ARA-M couldn't be selected: " + msg;
            Log.d(ACCESS_CONTROL_ENFORCER_TAG, msg);
            if (e instanceof NoSuchElementException) {
                mNoSuchElement = true;
                // SELECT failed
                // Access Rule Applet is not available => deny any access
                reason = " No Access because ARA-M is not available";
                Log.d(ACCESS_CONTROL_ENFORCER_TAG, msg );
                throw new SecurityException(reason);
            } else if( e instanceof MissingResourceException ){
                // re-throw exception
                // fixes issue 23
                // this indicates that no channel is left for accessing the SE element
                Log.d(ACCESS_CONTROL_ENFORCER_TAG, "no channels left to access ARA-M: " + e.getMessage() );
                throw (MissingResourceException)e;
            } else {
                // MANAGE CHANNEL failed or general error
                // In order to be compliant with any UICC/SIM card on the market
                // we are going to ignore the error and says that the ARA-M is not available.
                // This not fully compliant with GP spec by required for mass compatibility.
                mNoSuchElement = true;

                reason = msg;
                Log.d(ACCESS_CONTROL_ENFORCER_TAG," ARA-M can not be accessed: " + msg);
                throw new SecurityException(reason);
            }
        }   // End of Exception handling
        return channel;
    }


    /**
     * 
     * @return true if rules are read, false if not necessary or not available, but no error
     * @throws SecurityException
     */
    private boolean readAllAccessRules() throws SecurityException {
        try {
            byte[] data = mApplet.readAllAccessRules();
            // no data returned, but no exception
            // -> no rule.
            if( data == null ) {
                return false;
            }

            BerTlv tlv = Response_DO_Factory.createDO( data );
            if( tlv == null ) {
                throw new SecurityException("No valid data object found" );
            } if( tlv instanceof Response_ALL_AR_DO ){

                ArrayList<REF_AR_DO> array = ((Response_ALL_AR_DO)tlv).getRefArDos();
                if( array == null || array.size() == 0 ){
                    return false; // no rules
                } else {
                    for (REF_AR_DO ref_ar_do : array) {
                        this.mAccessRuleCache.putWithMerge(ref_ar_do.getRefDo(), ref_ar_do.getArDo());
                    }
                }
            } else {
                throw new SecurityException( "Applet returned invalid or wrong data object!");
            }
        } catch (ParserException e) {
            throw new SecurityException("Parsing Data Object Exception: " + e.getMessage());
        }
        return true;
    }
    
    private Channel openChannel(Terminal terminal, byte[] aid, ISmartcardServiceCallback callback) throws Exception {
        OpenLogicalChannelResponse rsp = terminal.internalOpenLogicalChannel(aid, (byte) 0x00);
        if (rsp == null) {
            return null;
        }
        Channel channel = new Channel(null, rsp.getChannel(), aid, rsp.getSelectResponse(), callback);

        // set access conditions to access ARA-M.
        ChannelAccess araChannelAccess = new ChannelAccess();
        araChannelAccess.setAccess(ChannelAccess.ACCESS.ALLOWED, ACCESS_CONTROL_ENFORCER_TAG);
        araChannelAccess.setApduAccess(ChannelAccess.ACCESS.ALLOWED);
        channel.setChannelAccess(araChannelAccess);

        return channel;
}

    private void closeChannel(Channel channel) {
        if (channel != null && channel.getChannelNumber() != 0) {
            try {
                mTerminal.internalCloseLogicalChannel(channel.getChannelNumber());
            } catch (Exception ignore) {
                Log.w(SmartcardService.LOG_TAG, "Error during internalCloseLogicalChannel", ignore);
            }
        }
    }
}
