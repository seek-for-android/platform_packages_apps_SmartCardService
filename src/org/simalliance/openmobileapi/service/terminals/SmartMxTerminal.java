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

package org.simalliance.openmobileapi.service.terminals;

import android.content.Context;
import android.nfc.INfcAdapterExtras;
import android.nfc.NfcAdapter;
import android.os.Binder;
import android.os.Bundle;
import android.util.Log;


import java.util.MissingResourceException;
import java.util.NoSuchElementException;

import org.simalliance.openmobileapi.service.CardException;
import org.simalliance.openmobileapi.service.SmartcardService;
import org.simalliance.openmobileapi.service.Terminal;


public class SmartMxTerminal extends Terminal {

    private INfcAdapterExtras ex;
	private Binder binder = new Binder();
	
    public SmartMxTerminal(Context context) {
        super(SmartcardService._eSE_TERMINAL, context);
    }

    public boolean isCardPresent() throws CardException {
    	try {
            NfcAdapter adapter =  NfcAdapter.getDefaultAdapter(mContext);
            if(adapter == null) {
                throw new CardException("Cannot get NFC Default Adapter");
            }
            return adapter.isEnabled();
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected void internalConnect() throws CardException {
        NfcAdapter adapter =  NfcAdapter.getDefaultAdapter(mContext);
        if(adapter == null) {
            throw new CardException("Cannot get NFC Default Adapter");
        }
        
        ex = adapter.getNfcAdapterExtrasInterface();
        if(ex == null)  {
            throw new CardException("Cannot get NFC Extra interface");
        }

		try {
            Bundle b = ex.open("org.simalliance.openmobileapi.service", binder);
            if (b == null) {
                throw new CardException("open SE failed");
            }
        } catch (Exception e) {
            throw new CardException("open SE failed");
        }
        mDefaultApplicationSelectedOnBasicChannel = true;
        mIsConnected = true;
    }

    @Override
    protected void internalDisconnect() throws CardException {
        try {
            Bundle b = ex.close("org.simalliance.openmobileapi.service", binder);
            if (b == null) {
                throw new CardException("close SE failed");
            }
        } catch (Exception e) {
            throw new CardException("close SE failed");
        }
    }

    @Override
    protected byte[] internalTransmit(byte[] command) throws CardException {
        try {
            Bundle b = ex.transceive("org.simalliance.openmobileapi.service", command);
            if (b == null) {
                throw new CardException("exchange APDU failed");
            }
            return b.getByteArray("out");
        } catch (Exception e) {
            throw new CardException("exchange APDU failed");
        }
    }

    @Override
    public byte[] getAtr() {
        return null;
    }

    @Override
    protected int internalOpenLogicalChannel() throws Exception {

    	mSelectResponse = null;
        byte[] manageChannelCommand = new byte[] {
                0x00, 0x70, 0x00, 0x00, 0x01
        };
        byte[] rsp = transmit(manageChannelCommand, 2, 0x9000, 0, "MANAGE CHANNEL");
        if ((rsp.length == 2) && ((rsp[0] == (byte) 0x68) && (rsp[1] == (byte) 0x81))) {
            throw new NoSuchElementException("logical channels not supported");
        }
        if (rsp.length == 2 && (rsp[0] == (byte) 0x6A && rsp[1] == (byte) 0x81)) {
            throw new MissingResourceException("no free channel available", "", "");
        }
        if (rsp.length != 3) {
            throw new MissingResourceException("unsupported MANAGE CHANNEL response data", "", "");
        }
        int channelNumber = rsp[0] & 0xFF;
        if (channelNumber == 0 || channelNumber > 19) {
            throw new MissingResourceException("invalid logical channel number returned", "", "");
        }

        return channelNumber;
    }

    @Override
    protected int internalOpenLogicalChannel(byte[] aid) throws Exception {

        if (aid == null) {
            throw new NullPointerException("aid must not be null");
        }
    	mSelectResponse = null;

        byte[] manageChannelCommand = new byte[] {
                0x00, 0x70, 0x00, 0x00, 0x01
        };
        byte[] rsp = transmit(manageChannelCommand, 2, 0x9000, 0, "MANAGE CHANNEL");
        if ((rsp.length == 2) && ((rsp[0] == (byte) 0x68) && (rsp[1] == (byte) 0x81))) {
            throw new NoSuchElementException("logical channels not supported");
        }
        if (rsp.length == 2 && (rsp[0] == (byte) 0x6A && rsp[1] == (byte) 0x81)) {
            throw new MissingResourceException("no free channel available", "", "");
        }
        if (rsp.length != 3) {
            throw new MissingResourceException("unsupported MANAGE CHANNEL response data", "", "");
        }
        int channelNumber = rsp[0] & 0xFF;
        if (channelNumber == 0 || channelNumber > 19) {
            throw new MissingResourceException("invalid logical channel number returned", "", "");
        }

        byte[] selectCommand = new byte[aid.length + 6];
        selectCommand[0] = (byte) channelNumber;
        if (channelNumber > 3) {
            selectCommand[0] |= 0x40;
        }
        selectCommand[1] = (byte) 0xA4;
        selectCommand[2] = 0x04;
        selectCommand[4] = (byte) aid.length;
        System.arraycopy(aid, 0, selectCommand, 5, aid.length);
        try {
        	mSelectResponse = transmit(selectCommand, 2, 0x9000, 0xFFFF, "SELECT");
        } catch (CardException exp) {
            internalCloseLogicalChannel(channelNumber);
            throw new NoSuchElementException(exp.getMessage());
        }

        return channelNumber;
    }

    @Override
    protected void internalCloseLogicalChannel(int channelNumber) throws CardException {
        if (channelNumber > 0) {
            byte cla = (byte) channelNumber;
            if (channelNumber > 3) {
                cla |= 0x40;
            }
            byte[] manageChannelClose = new byte[] {
                    cla, 0x70, (byte) 0x80, (byte) channelNumber
            };
            transmit(manageChannelClose, 2, 0x9000, 0xFFFF, "MANAGE CHANNEL");
        }
    }
}
