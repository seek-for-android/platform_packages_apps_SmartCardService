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
package org.simalliance.openmobileapi.service.security.arf;

import android.util.Log;

import org.simalliance.openmobileapi.service.ISmartcardServiceCallback;
import org.simalliance.openmobileapi.service.ITerminal;
import org.simalliance.openmobileapi.service.SmartcardService;
import org.simalliance.openmobileapi.service.security.AccessControlEnforcer;
import org.simalliance.openmobileapi.service.security.AccessRuleCache;
import org.simalliance.openmobileapi.service.security.arf.SecureElement;
import org.simalliance.openmobileapi.service.security.arf.PKCS15.PKCS15Handler;

public class ArfController {

	private PKCS15Handler mPkcs15Handler = null;
	private SecureElement mSecureElement = null;

	private AccessControlEnforcer mMaster = null;
    private AccessRuleCache mAccessRuleCache = null;
    private ITerminal mTerminal = null;
    
    public ArfController(AccessControlEnforcer master) {
    	mMaster = master;
    	mAccessRuleCache = mMaster.getAccessRuleCache();
    	mTerminal = mMaster.getTerminal();

    }
    
	public synchronized boolean initialize(ISmartcardServiceCallback callback) {

		
    	if( mSecureElement == null ){
    		mSecureElement = new SecureElement(this, mTerminal);
    	}
     	if( mPkcs15Handler == null ) {
    		mPkcs15Handler = new PKCS15Handler(mSecureElement);
    	}
    	return mPkcs15Handler.loadAccessControlRules(mTerminal.getName());
	}
    
    

	public AccessRuleCache getAccessRuleCache(){
		return mAccessRuleCache;
	}
}
