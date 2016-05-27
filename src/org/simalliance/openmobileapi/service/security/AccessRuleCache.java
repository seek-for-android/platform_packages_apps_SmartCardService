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

package org.simalliance.openmobileapi.service.security;

import java.io.PrintWriter;
import java.security.AccessControlException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.simalliance.openmobileapi.service.SmartcardService;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.AID_REF_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.AR_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Hash_REF_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.REF_DO;

import android.util.Log;


public class AccessRuleCache {
    // Previous "RefreshTag"
    // 2012-09-25
    // the refresh tag has to be valid as long as AxxController is valid
    // a pure static element would cause that rules are not read any longer once the AxxController is recreated.
    private byte[]  mRefreshTag=null;


    private Map<REF_DO, ChannelAccess> mRuleCache = new HashMap<>();

    /**
     * Clears access rule cache and refresh tag.
     */
    public void reset(){
        mRefreshTag = null;
        mRuleCache.clear();
    }

    /**
     * Clears access rule cache only.
     */
    public void clearCache(){
        mRuleCache.clear();
    }

    public ChannelAccess put(REF_DO ref_do_key, AR_DO ar_do) {

        ChannelAccess channelAccess = mapArDo2ChannelAccess( ar_do );
        this.mRuleCache.put(ref_do_key, channelAccess);
        return channelAccess;
    }

    public void putWithMerge( REF_DO ref_do, AR_DO ar_do ) {

        ChannelAccess channelAccess = mapArDo2ChannelAccess( ar_do );
        putWithMerge( ref_do, channelAccess );
    }

    public void putWithMerge( REF_DO ref_do, ChannelAccess channelAccess ) {

        if( mRuleCache.containsKey(ref_do)){
            ChannelAccess ca = mRuleCache.get(ref_do);
            Log.v(SmartcardService.LOG_TAG, "Access Rule with " + ref_do.toString() + " already exists.");

            // if new ac condition is more restrictive then use their settings

            // if new rule says NFC is denied then use it
            // if current rule as undefined NFC rule then use setting of new rule.
            // current NFC	new NFC		resulting NFC
            // UNDEFINED	x			x
            // ALLOWED		!DENIED 	ALLOWED
            // ALLOWED		DENIED 		DENIED
            // DENIED	 	!DENIED 	DENIED
            // DENEID		DENIED  	DENIED
            if( channelAccess.getNFCEventAccess() == ChannelAccess.ACCESS.DENIED ||
                    ca.getNFCEventAccess() == ChannelAccess.ACCESS.UNDEFINED ) {
                ca.setNFCEventAccess(channelAccess.getNFCEventAccess());
            }

            // if new rule says APUD is denied then use it
            // if current rule as undefined APDU rule then use setting of new rule.
            // current APDU	new APDU	resulting APDU
            // UNDEFINED	x			x
            // ALLOWED		!DENIED 	ALLOWED
            // ALLOWED		DENIED 		DENIED
            // DENIED	 	!DENIED 	DENIED
            // DENEID		DENIED  	DENIED
            if( channelAccess.getApduAccess() == ChannelAccess.ACCESS.DENIED ||
                    ca.getApduAccess() == ChannelAccess.ACCESS.UNDEFINED ) {
                ca.setApduAccess(channelAccess.getApduAccess());
            }

            // put APDU filter together if resulting APDU access is not denied.
            if (ca.getApduAccess() != ChannelAccess.ACCESS.DENIED) {
                if( channelAccess.isUseApduFilter() ){
                    ca.setUseApduFilter(true);
                    ApduFilter[] filter = ca.getApduFilter();
                    ApduFilter[] filter2 = channelAccess.getApduFilter();
                    if( filter == null || filter.length == 0 ){
                        ca.setApduFilter(filter2);
                    } else if( filter2 == null || filter2.length == 0){
                        ca.setApduFilter(filter);
                    } else {
                        ApduFilter[] sum = new ApduFilter[filter.length + filter2.length];
                        int i = 0;
                        for( ApduFilter f : filter ){
                            sum[i++] = f;
                        }
                        for( ApduFilter f : filter2 ){
                            sum[i++] = f;
                        }
                        ca.setApduFilter(sum);
                    }
                }
            } else {
                // if APDU access is not allowed the remove also all apdu filter
                ca.setUseApduFilter(false);
                ca.setApduFilter(null);
            }
            Log.v(SmartcardService.LOG_TAG, "Merged Access Rule: " + ca.toString());
            return;
        }
        mRuleCache.put(ref_do, channelAccess);
    }


    public ChannelAccess findAccessRule( byte[] aid, Certificate[] appCerts) throws AccessControlException {



        // TODO: check difference between DeviceCertHash and Certificate Chain (EndEntityCertHash, IntermediateCertHash (1..n), RootCertHash)
        // The DeviceCertificate is equal to the EndEntityCertificate.
        // The android systems seems always to deliver only the EndEntityCertificate, but this seems not to be sure.
        // thats why we implement the whole chain.

        AID_REF_DO aid_ref_do = getAidRefDo(aid);
        Hash_REF_DO hash_ref_do;
        REF_DO ref_do;

        // Search Rule A ( Certificate(s); AID )
        // walk through certificate chain.
        for( Certificate appCert : appCerts ){

            try {
                hash_ref_do = new Hash_REF_DO(AccessControlEnforcer.getAppCertHash(appCert));
                ref_do = new REF_DO(aid_ref_do, hash_ref_do);

                if( mRuleCache.containsKey( ref_do ) ){
                    return mRuleCache.get( ref_do );
                }
            } catch (CertificateEncodingException e) {
                throw new AccessControlException("Problem with Application Certificate.");
            }
        }
        // no rule found,
        // now we have to check if the given AID
        // is used together with another specific hash value (another device application)
        if( searchForRulesWithSpecificAidButOtherHash(aid_ref_do) != null ){
            Log.v(SmartcardService.LOG_TAG, "Conflict Resolution Case A returning access rule \'NEVER\'.");
            ChannelAccess ca = new ChannelAccess();
            ca.setApduAccess(ChannelAccess.ACCESS.DENIED);
            ca.setAccess(ChannelAccess.ACCESS.DENIED, "AID has a specific access rule with a different hash. (Case A)");
            ca.setNFCEventAccess(ChannelAccess.ACCESS.DENIED);
            return ca;
        }


        // SearchRule B ( <AllDeviceApplications>; AID)
        aid_ref_do =  getAidRefDo(aid);
        hash_ref_do = new Hash_REF_DO(); // empty hash ref
        ref_do = new REF_DO(aid_ref_do, hash_ref_do);

        if( mRuleCache.containsKey( ref_do ) ){
            return mRuleCache.get( ref_do );
        }

        // Search Rule C ( Certificate(s); <AllSEApplications> )
        aid_ref_do = new AID_REF_DO(AID_REF_DO._TAG);
        for( Certificate appCert : appCerts ){
            try {
                hash_ref_do = new Hash_REF_DO(AccessControlEnforcer.getAppCertHash(appCert));
                ref_do = new REF_DO(aid_ref_do, hash_ref_do);

                if( mRuleCache.containsKey( ref_do ) ){
                    return mRuleCache.get( ref_do );
                }
            } catch (CertificateEncodingException e) {
                throw new AccessControlException("Problem with Application Certificate.");
            }
        }

        // no rule found,
        // now we have to check if the all AID DO
        // is used together with another Hash
        if( this.searchForRulesWithAllAidButOtherHash() != null ){
            Log.v(SmartcardService.LOG_TAG, "Conflict Resolution Case C returning access rule \'NEVER\'.");
            ChannelAccess ca = new ChannelAccess();
            ca.setApduAccess(ChannelAccess.ACCESS.DENIED);
            ca.setAccess(ChannelAccess.ACCESS.DENIED, "An access rule with a different hash and all AIDs was found. (Case C)");
            ca.setNFCEventAccess(ChannelAccess.ACCESS.DENIED);
            return ca;
        }

        // SearchRule D ( <AllDeviceApplications>; <AllSEApplications>)
        aid_ref_do =  new AID_REF_DO(AID_REF_DO._TAG);
        hash_ref_do = new Hash_REF_DO();
        ref_do = new REF_DO(aid_ref_do, hash_ref_do);

        if( mRuleCache.containsKey( ref_do ) ){
            return mRuleCache.get( ref_do );
        }
        return null;
    }

    public static AID_REF_DO getAidRefDo( byte[] aid ){
        AID_REF_DO aid_ref_do;

        if( aid == null || aid.length == 0 ){
            aid_ref_do = new AID_REF_DO(AID_REF_DO._TAG_DEFAULT_APPLICATION);
        } else {
            aid_ref_do = new AID_REF_DO(AID_REF_DO._TAG, aid);
        }

        return aid_ref_do;
    }

    public static REF_DO buildHashMapKey( byte[] aid, byte[] appCertHash ){
        // Build key
        Hash_REF_DO hash_ref_do = new Hash_REF_DO(appCertHash);
        return new REF_DO(getAidRefDo(aid), hash_ref_do);
    }



    /*
     * The GP_SE_AC spec says:
     * According to the rule conflict resolution process defined in section 3.2.1, if a specific rule exists
     * that associates another device application with the SE application identified by AID (e.g. there is
     * a rule associating AID with the hash of another device application), then the ARA-M (when
     * using GET DATA [Specific]) or the Access Control Enforcer (when using GET DATA [All]) shall
     * set the result of SearchRuleFor(DeviceApplicationCertificate, AID) to NEVER (i.e. precedence
     * of specific rules over generic rules)
     *
     * In own words:
     * Search the rules cache for a rule that contains the wanted AID but with another specific Hash value.
     */
    private REF_DO searchForRulesWithSpecificAidButOtherHash(AID_REF_DO aid_ref_do) {

        // AID has to be specific
        if( aid_ref_do == null ){
            return null;
        }
        // C0 00 is specific -> default AID
        // 4F 00 is NOT specific -> all AIDs
        if( aid_ref_do.getTag() == AID_REF_DO._TAG &&
                (aid_ref_do.getAid() == null || aid_ref_do.getAid().length == 0)){
            return null;
        }

        Set<REF_DO> keySet = mRuleCache.keySet();
        for (REF_DO ref_do : keySet) {
            if (aid_ref_do.equals(ref_do.getAidDo())) {
                if (ref_do.getHashDo() != null &&
                        ref_do.getHashDo().getHash() != null &&
                        ref_do.getHashDo().getHash().length > 0) {
                    // this ref_do contains the search AID and a specific hash value
                    return ref_do;
                }
            }
        }
        return null;
    }

    /*
     * The GP_SE_AC spec says:
     * According to the rule conflict resolution process defined in section 3.2.1, if a specific rule exists
     * that associates another device application with the SE application identified by AID (e.g. there is
     * a rule associating AID with the hash of another device application), then the ARA-M (when
     * using GET DATA [Specific]) or the Access Control Enforcer (when using GET DATA [All]) shall
     * set the result of SearchRuleFor(DeviceApplicationCertificate, AID) to NEVER (i.e. precedence
     * of specific rules over generic rules)
     *
     * In own words:
     * Search the rules cache for a rule that contains a Hash with an all SE AID (4F 00).
    */
    private Object searchForRulesWithAllAidButOtherHash() {

        AID_REF_DO aid_ref_do = new AID_REF_DO(AID_REF_DO._TAG);

        Set<REF_DO> keySet = mRuleCache.keySet();
        for (REF_DO ref_do : keySet) {
            if (aid_ref_do.equals(ref_do.getAidDo())) {
                // aid tlv is equal
                if (ref_do.getHashDo() != null &&
                        (ref_do.getHashDo().getHash() != null && ref_do.getHashDo().getHash().length > 0)) {
                    // return ref_do if
                    // a HASH value is available and has a length > 0 (SHA1_LEN)
                    return ref_do;
                }
            }
        }
        return null;
    }

    public static ChannelAccess mapArDo2ChannelAccess(AR_DO ar_do ){
        ChannelAccess channelAccess = new ChannelAccess();

        // check apdu access allowance
        if( ar_do.getApduArDo() != null ){
            // first if there is a rule for access, reset the general deny flag.
            channelAccess.setAccess(ChannelAccess.ACCESS.ALLOWED, "");
            channelAccess.setUseApduFilter(false);

            if( ar_do.getApduArDo().isApduAllowed() ){
                // check the apdu filter
                ArrayList<byte[]> apduHeaders = ar_do.getApduArDo().getApduHeaderList();
                ArrayList<byte[]> filterMasks = ar_do.getApduArDo().getFilterMaskList();
                if( apduHeaders != null &&
                    filterMasks != null &&
                    apduHeaders.size() > 0 &&
                    apduHeaders.size() == filterMasks.size()  ){

                    ApduFilter[] accessConditions = new ApduFilter[apduHeaders.size()];
                    for( int i = 0; i < apduHeaders.size(); i++){
                        accessConditions[i] = new ApduFilter( apduHeaders.get(i), filterMasks.get(i));
                    }
                    channelAccess.setUseApduFilter(true);
                    channelAccess.setApduFilter(accessConditions);
                } else {
                    // general APDU access
                    channelAccess.setApduAccess(ChannelAccess.ACCESS.ALLOWED);
                }
            } else {
                // apdu access is not allowed at all.
                channelAccess.setApduAccess(ChannelAccess.ACCESS.DENIED);
            }
        } else {
            channelAccess.setAccess(ChannelAccess.ACCESS.DENIED, "No APDU access rule available.!");
        }

        // check for NFC Event allowance
        if( ar_do.getNfcArDo() != null ){
            channelAccess.setNFCEventAccess(ar_do.getNfcArDo().isNfcAllowed() ? ChannelAccess.ACCESS.ALLOWED : ChannelAccess.ACCESS.DENIED);
        } else {
            // GP says that by default NFC should have the same right as for APDU access
            channelAccess.setNFCEventAccess(channelAccess.getApduAccess());
        }
        return channelAccess;
    }

    public boolean isRefreshTagEqual(byte[]  refreshTag ) {
        return !(refreshTag == null || mRefreshTag == null)
                && Arrays.equals(refreshTag, mRefreshTag);
    }

    public byte[] getRefreshTag() {
        return mRefreshTag;
    }

    public void setRefreshTag(byte[] refreshTag) {
        this.mRefreshTag = refreshTag;
    }


    public void dump(PrintWriter writer, String prefix) {
        writer.println(prefix + SmartcardService.LOG_TAG + ":");
        prefix += "  ";

        /* Dump the refresh tag */
        writer.print(prefix + "Current refresh tag is: ");
        if(mRefreshTag == null)  writer.print("<null>");
        else for(byte oneByte: mRefreshTag) writer.printf("%02X:", oneByte);
        writer.println();

        /* Dump the rules cache */
        writer.println(prefix + "rules dump:");
        prefix += "  ";

        int i = 0;
        for (Map.Entry<REF_DO, ChannelAccess> entry : mRuleCache.entrySet()) {
            i++;
            writer.print(prefix + "rule " + i + ": ");
            writer.println(entry.getKey().toString());

            writer.print(prefix + "  ->");
            writer.println(entry.getValue().toString());
        }

        writer.println();
    }
}
