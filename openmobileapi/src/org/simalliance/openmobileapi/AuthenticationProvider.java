/*
 * Copyright 2013 Giesecke & Devrient GmbH.
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

package org.simalliance.openmobileapi;

import java.io.IOException;

import org.simalliance.openmobileapi.internal.ErrorStrings;
import org.simalliance.openmobileapi.util.CommandApdu;
import org.simalliance.openmobileapi.util.ResponseApdu;

/**
 * This Authentication class can be used to privilege a certain communication
 * channel to the Secure Element for operations that requires a PIN
 * authentication. Besides the PIN verification for authentication this class
 * provides also PIN management command for changing, deactivating or activating
 * PINs.
 * <p>
 * <b>Prerequisites:</b> The PIN operations performed by this
 * AuthenticationProvider class are based on the ISO/IEC 7816-4 specification
 * and require a preselected applet on the specified communication channel to
 * the Secure Element that implements ISO/IEC 7816-4 compliant PIN commands.
 * <p>
 * <b>Notes:</b>
 * <ul>
 * <li>If used by multiple threads, synchronization is up to the application.
 * <li>Each operation needs an access to the Secure Element. If the access can
 * not be granted because of a closed channel or a missing security condition
 * the called method will return an error.</li>
 * </ul>
 */
public class AuthenticationProvider extends Provider {

    /**
     * Encapsulates the defined channel by an AuthenticationProvider object that
     * can be used for applying PIN commands on it.
     *
     * @param channel The channel that should be privileged for operations that
     *        requires a PIN authentication.
     *
     * @throws IllegalStateException if the defined channel is closed.
     */
    public AuthenticationProvider(Channel channel)
            throws IllegalStateException {
        super(channel);
    }

    /**
     * Performs a PIN verification.
     *
     * @param pinID The PIN ID references the PIN in the Secure Element which
     *        shall be used for the verification.
     * @param pin The PIN that shall be verified.
     *
     * @return True if the authentication was successful, False if the
     *         authentication fails.
     *
     * @throws IllegalArgumentException if the PIN reference as defined couldn't
     *         be found in the Secure Element.
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the PIN value has a bad coding or a
     *         wrong length (empty or too long).
     * @throws IllegalStateException if the used channel is closed.
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public boolean verifyPin(PinID pinID, byte[] pin)
            throws IllegalArgumentException, IllegalStateException,
            UnsupportedOperationException, IOException {

        if (pinID == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("pinID"));
        }
        if (pin == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("pin"));
        }

        if (pin.length == 0 || pin.length > CommandApdu.MAX_DATA_LENGTH) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("pin"));
        }

        // Prepare and send the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_VERIFY_20);
        apdu.setP1((byte) 0x00);
        byte p2 = (byte) pinID.getID();
        if (pinID.isLocal()) {
            // Set first bit to 1 to indicate that it is a local pin
            p2 = (byte) (p2 | 0x80);
        }
        apdu.setP2(p2);
        apdu.setData(pin);
        byte[] apduResponse = apdu.sendApdu();

        // Parse the response
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            return true;
        case ResponseApdu.SW_63_NO_INFO:
            // ISO/IEC 7816-4 7.5.1: "In this group of commands, SW1-SW2 set to
            // 6300 or 63CX indicates that the verification failed [...]"
            return false;
        case ResponseApdu.SW_AUTH_METHOD_BLOCKED:
            // PIN is blocked.
            return false;
        case ResponseApdu.SW_REF_DATA_NOT_USABLE:
            // PIN is blocked.
            return false;
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        case ResponseApdu.SW_INCORRECT_P1P2:
            // Wrong PIN ID.
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_REF_NOT_FOUND:
            // Wrong PIN ID.
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_WRONG_PARAMETERS_P1P2:
            // Wrong PIN ID.
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        default:
            // Check if SW is between 63C0 and 63CF
            if (ResponseApdu.SW_CTR_MIN <= swValue
                    && swValue <= ResponseApdu.SW_CTR_MAX) {
                return false;
            } else {
                throw new IOException(
                        ErrorStrings.unexpectedStatusWord(swValue));
            }
        }
    }

    /**
     * Changes the PIN.
     * <p>
     * <b>Note:</b> This method is based on the ISO/IEC 7816-4 command CHANGE
     * REFERENCE DATA.
     *
     * @param pinID The PIN ID references the PIN in the Secure Element which
     *        shall be changed.
     * @param oldPin The old PIN that shall be changed.
     * @param newPin The PIN that shall be set as new PIN.
     *
     * @throws SecurityException if old PIN does not match with the PIN stored
     *         in the SE. The PIN is not changed.
     * @throws IllegalArgumentException if the PIN reference as defined couldn't
     *         be found in the Secure Element.
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the value of oldPin or newPIN has a
     *         bad coding or a wrong length (empty or too long).
     * @throws IllegalStateException if the used channel is closed.
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public void changePin(PinID pinID, byte[] oldPin, byte[] newPin)
            throws SecurityException, IllegalArgumentException,
            IllegalStateException, UnsupportedOperationException, IOException {

        if (pinID == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("pinID"));
        }
        if (oldPin == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("oldPin"));
        }
        if (newPin == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("newPin"));
        }

        if (oldPin.length == 0) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("oldPin"));
        }
        if (newPin.length == 0) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("newPin"));
        }

        // No need to check if pins are too long since it
        // will be done by setData

        // Prepare the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_CHANGE_REF_DATA);
        apdu.setP1((byte) 0x00);
        byte p2 = (byte) pinID.getID();
        if (pinID.isLocal()) {
            // Set first bit to 1 to indicate that is a local pin
            p2 = (byte) (p2 | 0x80);
        }
        apdu.setP2(p2);
        byte[] data = new byte[oldPin.length + newPin.length];
        System.arraycopy(oldPin, 0, data, 0, oldPin.length);
        System.arraycopy(newPin, 0, data, oldPin.length, newPin.length);
        apdu.setData(data);
        byte[] apduResponse = apdu.sendApdu();

        // Parse the response
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            // Everything is OK.
            break;
        case ResponseApdu.SW_63_NO_INFO:
            // ISO/IEC 7816-4 7.5.1: "In this group of commands, SW1-SW2 set to
            // 6300 or 63CX indicates that the verification failed [...]"
            throw new SecurityException(ErrorStrings.PIN_WRONG);
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_AUTH_METHOD_BLOCKED:
            // PIN is blocked.
            throw new SecurityException(ErrorStrings.PIN_BLOCKED);
        case ResponseApdu.SW_REF_DATA_NOT_USABLE:
            // PIN is blocked.
            throw new SecurityException(ErrorStrings.PIN_BLOCKED);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        case ResponseApdu.SW_INCORRECT_P1P2:
            // Wrong PIN ID.
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_WRONG_PARAMETERS_P1P2:
            // Wrong PIN ID.
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        default:
            // Check if SW is between 63C0 and 63CF
            if (ResponseApdu.SW_CTR_MIN <= swValue
                    && swValue <= ResponseApdu.SW_CTR_MAX) {
                // oldPin is wrong
                throw new SecurityException(ErrorStrings.PIN_WRONG);
            } else {
                throw new IOException(
                        ErrorStrings.unexpectedStatusWord(swValue));
            }
        }
    }

    /**
     * Resets the PIN with the reset PIN or just resets the retry counter.
     * <p>
     * <b>Note:</b> This method is based on the ISO/IEC 7816-4 command RESET
     * RETRY COUNTER.
     *
     * @param pinID The PIN ID references the PIN in the Secure Element which
     *        shall be reset.
     * @param resetPin The reset PIN that shall be used for reset.
     * @param newPin The PIN that shall be set as new PIN. Can be omitted with
     *        null if just the reset counter shall be reset.
     *
     * @throws SecurityException if resetPin does not match with the "resetPin"
     *         stored in the SE. The PIN or reset counter is not changed.
     * @throws IllegalArgumentException if the PIN ID reference as defined
     *         couldn't be found in the secure element.
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the value of resetPin or newPin has a
     *         bad coding or a wrong length (empty or too long).
     * @throws IllegalStateException if the used channel is closed.
     * @throws UnsupportedOperationException if the resetPin is not defined, or
     *         if the operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public void resetPin(PinID pinID, byte[] resetPin, byte[] newPin)
            throws SecurityException, IllegalArgumentException,
            IllegalStateException, UnsupportedOperationException, IOException {

        if (pinID == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("pinID"));
        }
        if (resetPin == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("resetPin"));
        }

        if (resetPin.length == 0) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("resetPin"));
        }
        if (newPin != null && newPin.length == 0) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("newPin"));
        }

        // No need to check if pins are too long since it will be done by
        // setData

        // Prepare and send the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_RESET_RETRY_CTR);
        // P1 depends on whether user wants to set a new PIN or only the
        // retry counter.
        if (newPin != null) {
            apdu.setP1((byte) 0x00);
        } else {
            apdu.setP1((byte) 0x01);
        }
        byte p2 = (byte) pinID.getID();
        if (pinID.isLocal()) {
            // Set first bit to 1 to indicate that it is a local pin
            p2 = (byte) (p2 | 0x80);
        }
        apdu.setP2(p2);
        byte[] data;
        // Data will be different depending on whether user wants to reset
        // PIN or only reset the retry counter.
        if (newPin != null) {
            data = new byte[resetPin.length + newPin.length];
        } else {
            data = new byte[resetPin.length];
        }

        System.arraycopy(resetPin, 0, data, 0, resetPin.length);
        if (newPin != null) {
            System.arraycopy(newPin, 0, data, resetPin.length, newPin.length);
        }
        apdu.setData(data);
        byte[] response = apdu.sendApdu();

        // Parse the response
        int swValue = ResponseApdu.getResponseStatusWordValue(response);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            // Everything is OK.
            break;
        case ResponseApdu.SW_63_NO_INFO:
            // ISO/IEC 7816-4 7.5.1: "In this group of commands, SW1-SW2 set to
            // 6300 or 63CX indicates that the verification failed [...]"
            throw new SecurityException(ErrorStrings.PIN_WRONG);
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_AUTH_METHOD_BLOCKED:
            // PIN is blocked.
            throw new SecurityException(ErrorStrings.PIN_BLOCKED);
        case ResponseApdu.SW_REF_DATA_NOT_USABLE:
            // PIN is blocked.
            throw new SecurityException(ErrorStrings.PIN_BLOCKED);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        case ResponseApdu.SW_INCORRECT_P1P2:
            // Wrong PIN ID.
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_WRONG_PARAMETERS_P1P2:
            // Wrong PIN ID.
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        default:
            if (ResponseApdu.SW_CTR_MIN <= swValue
                    && swValue <= ResponseApdu.SW_CTR_MAX) {
                // resetPin is wrong
                throw new SecurityException(ErrorStrings.PIN_WRONG);
            } else {

                throw new IOException(
                        ErrorStrings.unexpectedStatusWord(swValue));
            }
        }
    }

    /**
     * Returns the retry counter of the referenced PIN.
     * <p>
     * <b>Note: </b> This method is based on the ISO/IEC 7816-4 command VERIFY.
     *
     * @param pinID The PIN ID references the PIN in the Secure Element and its
     *        retry counter.
     *
     * @return The retry counter of the referenced PIN.
     *
     * @throws IllegalArgumentException if the PIN reference as defined couldn't
     *         be found in the Secure Element.
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalStateException if the used channel is closed or if PIN
     *         PIN verification is not required for this pinID.
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     * @throws IllegalArgumentException if pinID is null.
     */
    public int getRetryCounter(PinID pinID) throws IllegalArgumentException,
            IllegalStateException, UnsupportedOperationException, IOException {

        if (pinID == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("pinID"));
        }

        // Prepare and send the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_VERIFY_20);
        apdu.setP1((byte) 0x00);
        byte p2 = (byte) pinID.getID();
        if (pinID.isLocal()) {
            // Set first bit to 1 to indicate that is a local pin
            p2 = (byte) (p2 | 0x80);
        }
        apdu.setP2(p2);
        byte[] response = apdu.sendApdu();

        // Parse the response
        int swValue = ResponseApdu.getResponseStatusWordValue(response);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            // This means that no PIN verification is required,
            // so we can't get the retry counter.
            throw new UnsupportedOperationException();
        case ResponseApdu.SW_63_NO_INFO:
            // ISO/IEC 7816-4 7.5.1: "In this group of commands, SW1-SW2 set to
            // 6300 or 63CX indicates that the verification failed [...]"
            throw new SecurityException(ErrorStrings.PIN_WRONG);
        case ResponseApdu.SW_AUTH_METHOD_BLOCKED:
            // PIN is blocked.
            throw new SecurityException(ErrorStrings.PIN_BLOCKED);
        case ResponseApdu.SW_REF_DATA_NOT_USABLE:
            // PIN is blocked.
            throw new SecurityException(ErrorStrings.PIN_BLOCKED);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        case ResponseApdu.SW_INCORRECT_P1P2:
            // Wrong PIN ID.
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_WRONG_PARAMETERS_P1P2:
            // Wrong PIN ID.
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        default:
            if (ResponseApdu.SW_CTR_MIN <= swValue
                    && swValue <= ResponseApdu.SW_CTR_MAX) {
                // Get the last 4 bits of the SW (63CX)
                return (int) swValue & 0x000F;
            } else {
                throw new IOException(
                        ErrorStrings.unexpectedStatusWord(swValue));
            }
        }
    }

    /**
     * Activates the PIN. Thus a deactivated PIN can be used again.
     * <p>
     * <b>Note:</b> This method is based on the ISO/IEC 7816-4 command ENABLE
     * VERIFICATION REQUIREMENT.
     *
     * @param pinID The PIN ID references the PIN in the Secure Element which
     *        shall be activated
     * @param pin the verification PIN for activating the PIN if required. Can
     *        be omitted with null if not required.
     *
     * @throws SecurityException if the defined pin does not match with the PIN
     *         needed for the activation. The PIN state will not be changed.
     * @throws IllegalStateException if the used channel is closed.
     * @throws IllegalArgumentException if the PIN reference as defined couldn't
     *         be found in the Secure Element
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the PIN value has a bad coding or a
     *         wrong length (empty or too long).
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public void activatePin(PinID pinID, byte[] pin) throws SecurityException,
            IllegalStateException, IllegalArgumentException,
            UnsupportedOperationException, IOException {

        if (pinID == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("pinID"));
        }

        if (pin != null) {
            if (pin.length == 0 || pin.length > CommandApdu.MAX_DATA_LENGTH) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidArrayLength("pin"));
            }
        }

        // Prepare and send the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_ENABLE_VERIF_REQ);
        if (pin != null) {
            apdu.setP1((byte) 0x00);
        } else {
            apdu.setP1((byte) 0x01);
        }
        byte p2 = (byte) pinID.getID();
        if (pinID.isLocal()) {
            // Set first bit to 1 to indicate that is a local pin
            p2 = (byte) (p2 | 0x80);
        }
        apdu.setP2(p2);
        if (pin != null) {
            apdu.setData(pin);
        }
        byte[] apduResponse = apdu.sendApdu();

        // Parse the response
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            // Everything is OK.
            break;
        case ResponseApdu.SW_63_NO_INFO:
            // Verification failed
            throw new SecurityException(ErrorStrings.PIN_WRONG);
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_AUTH_METHOD_BLOCKED:
            throw new SecurityException(ErrorStrings.AUTH_METHOD_BLOCKED);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException(
                    ErrorStrings.OPERATION_NOT_SUPORTED);
        case ResponseApdu.SW_INCORRECT_P1P2:
            if (pin != null) {
                // pinID is wrong
                // TODO: should be an IllegalReferenceError
                throw new IllegalArgumentException(
                        ErrorStrings.PIN_REF_NOT_FOUND);
            } else {
                // Either pinID is wrong (IllegalReferenceError), or
                // this pinID does not support activation with pin = null
                // (IllegalParameterError)
                // TODO: differentiate between cases
                // TODO: should be an IllegalReferenceError (in one case)
                throw new IllegalArgumentException(
                        "Either pinID is wrong, or this pin does not "
                        + "support activation with pin = null.");
            }
        case ResponseApdu.SW_REF_NOT_FOUND:
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_WRONG_PARAMETERS_P1P2:
            if (pin != null) {
                // pinID is wrong
                // TODO: should be an IllegalReferenceError
                throw new IllegalArgumentException(
                        ErrorStrings.PIN_REF_NOT_FOUND);
            } else {
                // Either pinID is wrong (IllegalReferenceError), or
                // this pinID does not support activation with pin = null
                // (IllegalParameterError)
                // TODO: differentiate between cases
                // TODO: should be an IllegalReferenceError (in one case)
                throw new IllegalArgumentException(
                        "Either pinID is wrong, or this pin does not "
                        + "support activation with pin = null.");
            }
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException(
                    ErrorStrings.OPERATION_NOT_SUPORTED);
        default:
            if (ResponseApdu.SW_CTR_MIN <= swValue
                    && swValue <= ResponseApdu.SW_CTR_MAX) {
                throw new SecurityException(ErrorStrings.PIN_WRONG);
            } else {
                throw new IOException(
                        ErrorStrings.unexpectedStatusWord(swValue));
            }
        }
    }

    /**
     * Deactivates the PIN. Thus the objects which are protected by the PIN can
     * now be used without this restriction until activatePin() is called.
     * <p>
     * <b>Note - </b> This method is based on the ISO/IEC 7816-4 command DISABLE
     * VERIFICATION REQUIREMENT.
     *
     * @param pinID The PIN ID references the PIN in the Secure Element which
     *        shall be deactivated.
     * @param pin the verification PIN for deactivating the pin if required. Can
     *        be omitted with null if not required.
     *
     * @throws SecurityException if the defined pin does not match with the PIN
     *         needed for the deactivation. The PIN state will not be changed.
     * @throws IllegalStateException if the used channel is closed.
     * @throws IllegalArgumentException if the PIN reference as defined couldn't
     *         be found in the Secure Element
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the PIN value has a bad coding or a
     *         wrong length (empty or too long).
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public void deactivatePin(final PinID pinID, final byte[] pin)
            throws SecurityException, IllegalStateException,
            IllegalArgumentException, UnsupportedOperationException,
            IOException {

        if (pinID == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("pinID"));
        }

        if (pin != null) {
            if (pin.length == 0 || pin.length > CommandApdu.MAX_DATA_LENGTH) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidArrayLength("pin"));
            }
        }

        // Prepare and send the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_DISABLE_VERIF_REQ);
        if (pin != null) {
            apdu.setP1((byte) 0x00);
        } else {
            apdu.setP1((byte) 0x01);
        }
        byte p2 = (byte) pinID.getID();
        if (pinID.isLocal()) {
            // Set first bit to 1 to indicate that is a local pin
            p2 = (byte) (p2 | 0x80);
        }
        apdu.setP2(p2);
        if (pin != null) {
            apdu.setData(pin);
        }
        byte[] apduResponse = apdu.sendApdu();

        // Parse the response
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            // Everything is OK.
            break;
        case ResponseApdu.SW_63_NO_INFO:
            // ISO/IEC 7816-4 7.5.1: "In this group of commands, SW1-SW2 set to
            // 6300 or 63CX indicates that the verification failed [...]"
            throw new SecurityException(ErrorStrings.PIN_WRONG);
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_AUTH_METHOD_BLOCKED:
            // PIN is blocked.
            throw new SecurityException(ErrorStrings.PIN_BLOCKED);
        case ResponseApdu.SW_REF_DATA_NOT_USABLE:
            // PIN is blocked.
            throw new SecurityException(ErrorStrings.PIN_BLOCKED);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        case ResponseApdu.SW_INCORRECT_P1P2:
            // Wrong PIN ID.
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_WRONG_PARAMETERS_P1P2:
            // Wrong PIN ID.
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.PIN_REF_NOT_FOUND);
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        default:
            if (ResponseApdu.SW_CTR_MIN <= swValue
                    && swValue <= ResponseApdu.SW_CTR_MAX) {
                throw new SecurityException(ErrorStrings.PIN_WRONG);
            } else {
                throw new IOException(
                        ErrorStrings.unexpectedStatusWord(swValue));
            }
        }
    }

    /**
     * This PIN ID uniquely identifies a PIN in the Secure Element system. The
     * PIN ID is defined as specified in ISO/IEC 7816-4 and can be used to
     * reference a PIN in an ISO/IEC 7816-4 compliant system.
     */
    public class PinID {

        /**
         * The minimum possible value of a PIN ID.
         */
        public static final int MIN_ID_VALUE = 0x00;

        /**
         * The maximum possible value of a PIN ID.
         */
        public static final int MAX_ID_VALUE = 0x1F;

        /**
         * The ID of the PIN (value from 0x00 to 0x1F).
         */
        private int mId;

        /**
         * Defines the scope (global or local). True if the PIN is local.
         * Otherwise false.
         */
        private boolean mLocal;

        /**
         * Creates a PIN ID (reference) to identify a PIN within a Secure
         * Element. The created PIN ID (as immutable object) can be specified on
         * all PIN operation methods provided by the AuthenticationProvider
         * class.
         * <p>
         * <b>Note:</b> This constructor is based on the P2 reference data for
         * PIN related commands as specified in ISO/IEC 7816-4 in chapter 7.5
         * (Basic security handling). Local set to true indicates specific
         * reference data and local set to false indicates global reference data
         * according to ISO/IEC 7816-4. The ID indicates the number of the
         * reference data (qualifier) according to ISO/IEC 7816-4.
         *
         * @param id The ID of the PIN (value from 0x00 to 0x1F).
         * @param local Defines the scope (global or local). True if the PIN is
         *        local. Otherwise false.
         *
         * @throws IllegalArgumentException if the defined ID is invalid.
         */
        public PinID(int id, boolean local)
                throws IllegalArgumentException {
            if ((id < MIN_ID_VALUE) || (id > MAX_ID_VALUE)) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidValue("id"));
            }

            mId = id;
            mLocal = local;
        }

        /**
         * Returns the PIN ID.
         * <p>
         * <b>Note:</b> This method is based on the P2 reference data for PIN
         * related commands as specified in ISO/IEC 7816-4 in chapter 7.5 (Basic
         * security handling). The ID indicates the number of the reference data
         * (qualifier) according to ISO/IEC 7816-4.
         *
         * @return The PIN ID.
         */
        public final int getID() {
            return mId;
        }

        /**
         * Identifies if the PIN is local or global.
         * <p>
         * <b>Note:</b> This method is based on the P2 reference data for PIN
         * related commands as specified in ISO/IEC 7816-4 in chapter 7.5 (Basic
         * security handling). Local set to true indicates specific reference
         * data and local set to false indicates global reference data according
         * to ISO/IEC 7816-4.
         *
         * @return True if the PIN is local. Otherwise false.
         */
        public final boolean isLocal() {
            return mLocal;
        }
    }
}
