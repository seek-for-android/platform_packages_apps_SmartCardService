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
import java.util.ArrayList;

import org.simalliance.openmobileapi.internal.ByteArrayConverter;
import org.simalliance.openmobileapi.internal.ErrorStrings;
import org.simalliance.openmobileapi.util.CommandApdu;
import org.simalliance.openmobileapi.util.ResponseApdu;

/**
 * This class provides an API to store and retrieve data on the SE which is
 * protected in a secure environment. A default set of functionality that is
 * always provided on every platform enable application developers to rely on
 * this interface for secure data storage (e.g. credit cards numbers, private
 * phone numbers, passwords, ...). The interface should encapsulate any SE
 * specifics as it is intended for device application developers who might not
 * be familiar with SE or APDU internals.
 *
 * @author G&D Barcelona, 2013
 * @version 1.0
 */
public class SecureStorageProvider extends Provider {

    // TODO check value of SES_SW_SECURITY_STATUS_NOT_SATISFIED (not ISO compliant).

    /**
     * Maximum length for a SS title.
     */
    public static final int MAX_TITLE_LENGTH = 60;

    /**
     * Creates a SecureStorageProvider instance which will be connected to the
     * preselected SE Secure Storage Applet on defined channel.
     *
     * @param channel the channel that shall be used by this Provider for
     *        operations on the Secure Storage.
     *
     * @throws IllegalStateException if the defined channel is closed.
     * @throws IllegalStateException if the defined channel is not connected to
     *        a Secure Storage applet.
     */
    public SecureStorageProvider(Channel channel) throws IllegalStateException {
        super(channel);
        if (!sendPingCommand()) {
            throw new IllegalStateException(ErrorStrings.SES_APP_NOT_PRESENT);
        }
    }

    /**
     * This command creates a Secure Storage entry with the defined title and
     * data. The data can contain an uninterpreted byte stream of an undefined
     * max length (e.g. names,numbers,image,media data,...).
     *
     * @param title The title of the entry that shall be written. The max. title
     *        length is 60. All characters must be supported by UTF-8.
     * @param data The data of the entry that shall be written. If data is empty
     *        or null then only the defined title will be assigned to the new
     *        entry.
     *
     * @throws SecurityException if old PIN to access the Secure Storage Applet
     *         was not verified.
     * @throws IllegalStateException if the used channel is closed.
     * @throws IllegalArgumentException if the title already exists, if the data
     *         chain is too long or if the title has bad encoding or wrong
     *         length (empty or too long).
     * @throws IOException if the entry couldn't be created because of an
     *         incomplete write procedure.
     */
    public void create(String title, byte[] data) throws IllegalStateException,
            IllegalArgumentException, SecurityException, IOException {

        int id = 0;

        if (title == null) {
            throw new IllegalArgumentException(ErrorStrings.paramNull("title"));
        }
        if (title.length() == 0) {
            throw new IllegalArgumentException(ErrorStrings.SES_EMPTY_TITLE);
        }
        if (title.length() > MAX_TITLE_LENGTH) {
            throw new IllegalArgumentException(ErrorStrings.SES_LONG_TITLE);
        }

        // Try creating the entry
        try {
            id = sendCreateEntryCommand(title);
        } catch (ProcessingException e) {
            switch (e.getSwValue()) {
            case ResponseApdu.SES_SW_MEMORY_FAILURE:
                throw new IOException(ErrorStrings.SES_CREATE_FAILED_MEMORY);
            case ResponseApdu.SES_SW_INCORRECT_COMMAND_DATA:
                throw new IllegalArgumentException(
                        ErrorStrings.SES_TITLE_EXISTS);
            case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                throw new SecurityException(
                        ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
            case ResponseApdu.SES_SW_NOT_ENOUGH_MEMORY:
                throw new IOException(ErrorStrings.SES_NOT_ENOUGH_MEMORY);
            default:
                throw new IOException(ErrorStrings.unexpectedStatusWord(e
                        .getSwValue()));
            }
        }

        // When entry is created, if there is data, start putting it.
        if (data != null && data.length != 0) {
            // Try selecting the entry
            try {
                sendSelectCommand(id);
            } catch (ProcessingException e) {
                // If an exception occurs during the select process,
                // then the create file action has to be undone.
                try {
                    sendDeleteEntryCommand(id);
                } catch (ProcessingException t) {
                }

                throw new IOException(
                        "Create process failed. Select operation failed: "
                                + ErrorStrings.unexpectedStatusWord(e
                                        .getSwValue()));
            } catch (IOException e) {
                try {
                    sendDeleteEntryCommand(id);
                } catch (ProcessingException t) {
                }

                throw e;
            }

            // Send the size of the data that will be sent
            try {
                sendPutDataCommand(data.length);
            } catch (ProcessingException e) {
                try {
                    sendDeleteEntryCommand(id);
                } catch (ProcessingException t) {
                }
                if (e.getSwValue() == ResponseApdu.
                        SES_SW_MEMORY_FAILURE) {
                    throw new IllegalArgumentException(
                            ErrorStrings.SES_CREATE_FAILED_MEMORY);
                }
                if (e.getSwValue() == ResponseApdu.
                        SES_SW_MEMORY_FAILURE) {
                    throw new IllegalArgumentException(
                            ErrorStrings.SES_CREATE_FAILED_MEMORY);
                } else {
                    throw new IOException(
                            "Create process failed. Put data operation failed: "
                                    + ErrorStrings.unexpectedStatusWord(e
                                            .getSwValue()));
                }
            } catch (IOException e) {
                try {
                    sendDeleteEntryCommand(id);
                } catch (ProcessingException t) {
                }

                throw e;
            }

            // Start sending effective data
            for (int position = 0; position < data.length;) {
                int remainingBytes = data.length - position;
                // Decide how many bytes will be sent in the next
                // iteration
                int currentBufferSize;
                if (remainingBytes < CommandApdu.MAX_DATA_LENGTH) {
                    currentBufferSize = remainingBytes;
                } else {
                    currentBufferSize = CommandApdu.MAX_DATA_LENGTH;
                }

                // Initialize and fill the buffer.
                byte[] buffer = new byte[currentBufferSize];
                System.arraycopy(data, position, buffer, 0, currentBufferSize);

                // Decide P1
                PutDataP1 p1;
                if (position == 0) {
                    p1 = PutDataP1.First;
                } else {
                    p1 = PutDataP1.Next;
                }

                // Put data
                try {
                    sendPutDataCommand(p1, buffer);
                } catch (ProcessingException e) {
                    try {
                        sendDeleteEntryCommand(id);
                    } catch (ProcessingException t) {
                    }
                    if (e.getSwValue() == ResponseApdu.
                            SES_SW_MEMORY_FAILURE) {
                        throw new IllegalArgumentException(
                                ErrorStrings.SES_CREATE_FAILED_MEMORY);
                    }
                    if (e.getSwValue() == ResponseApdu.
                            SES_SW_NOT_ENOUGH_MEMORY) {
                        throw new IllegalArgumentException(
                                ErrorStrings.SES_NOT_ENOUGH_MEMORY);
                    } else {
                        throw new IOException(
                                "Create process failed. Put data operation "
                                        + "failed: "
                                        + ErrorStrings.unexpectedStatusWord(e
                                                .getSwValue()));
                    }
                } catch (IOException e) {
                    try {
                        sendDeleteEntryCommand(id);
                    } catch (ProcessingException t) {
                    }

                    throw e;
                }

                // If everything worked, update the position
                position += currentBufferSize;
            }
        }
    }

    /**
     * This command updates the data of the Secure Storage entry referenced by
     * the defined title. The data can contain an uninterpreted byte stream
     *  of an undefined max length (e.g. names, numbers, image,
     *  media data, ...).
     *
     * @param title the title of the entry that must already exist. The max.
     * title length is 60. All characters must be supported by UTF-8.
     * @param data the data of the entry that shall be written. If data is
     * empty or null then the data of the existing entry (referenced by the
     * title) will be deleted.

     *
     * @throws IllegalStateException if the used channel is closed.
     * @throws IllegalArgumentException if the title does not already exists.
     * @throws IllegalArgumentException if the title is incorrect: bad encoding
     * or wrong length (empty or too long).
     * @throws IllegalArgumentException if the data chain is too long.

     * @throws IOException if the entry couldn’t be updated because of an
     * incomplete write procedure.
     * @throws SecurityException if the PIN to access the Secure Storage Applet
     * was not verified.
     */
    public void update(String title, byte[] data) throws IllegalStateException,
            IllegalArgumentException, SecurityException, IOException {

        int id;
        if (title == null) {
            throw new IllegalArgumentException(ErrorStrings.paramNull("title"));
        }
        if (title.length() == 0) {
            throw new IllegalArgumentException(ErrorStrings.SES_EMPTY_TITLE);
        }
        if (title.length() > MAX_TITLE_LENGTH) {
            throw new IllegalArgumentException(ErrorStrings.SES_LONG_TITLE);
        }

        if (data == null) {
            data = new byte[0];
        }

        try {
            id = sendGetIdCommand(title);
        } catch (ProcessingException e) {
            switch (e.getSwValue()) {
            case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                throw new SecurityException(
                        ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
            case ResponseApdu.SES_SW_REF_NOT_FOUND:
                throw new IllegalArgumentException(ErrorStrings.
                        SES_NO_ENTRY_SELECTED);
            default:
                throw new IOException(ErrorStrings.unexpectedStatusWord(e
                        .getSwValue()));
            }
        }

        try {
            sendSelectCommand(id);
        } catch (ProcessingException e) {
            switch (e.getSwValue()) {
            case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                throw new SecurityException(
                        ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
            default:
                throw new IOException(ErrorStrings.unexpectedStatusWord(e
                        .getSwValue()));
            }
        }

        // previous data has to be caught to undo changes if some action is
        // wrong done.
        byte[] previousData = read(title);
        // nothing to be done if an error occurs. Nothing was done before.
        try {
            sendPutDataCommand(data.length);
        } catch (ProcessingException e) {
            switch (e.getSwValue()) {
            case ResponseApdu.SES_SW_MEMORY_FAILURE:
                throw new IllegalArgumentException(
                        ErrorStrings.SES_CREATE_FAILED_MEMORY);
            case ResponseApdu.SES_SW_NOT_ENOUGH_MEMORY:
                throw new IllegalArgumentException(
                        ErrorStrings.SES_NOT_ENOUGH_MEMORY);
            default:
                throw new IOException(ErrorStrings.unexpectedStatusWord(e
                        .getSwValue()));
            }
        }

        // Start sending effective data
        for (int position = 0; position < data.length;) {
            int remainingBytes = data.length - position;
            // Decide how many bytes will be sent in the next
            // iteration
            byte[] buffer;
            if (remainingBytes < CommandApdu.MAX_DATA_LENGTH) {
                buffer = new byte[remainingBytes];
            } else {
                buffer = new byte[remainingBytes];
            }
            // Initialize and fill the buffer.
            System.arraycopy(data, position, buffer, 0, buffer.length);

            // Decide P1
            PutDataP1 p1;
            if (position == 0) {
                p1 = PutDataP1.First;
            } else {
                p1 = PutDataP1.Next;
            }

            // Put data
            try {
                sendPutDataCommand(p1, buffer);
            } catch (ProcessingException e) {
                try {
                    sendDeleteEntryCommand(id);
                    create(title, previousData);
                } catch (ProcessingException t) {
                }
                if (e.getSwValue() == ResponseApdu.
                        SES_SW_MEMORY_FAILURE) {
                    throw new IllegalArgumentException(
                            ErrorStrings.SES_CREATE_FAILED_MEMORY);
                }
                if (e.getSwValue() == ResponseApdu.
                        SES_SW_NOT_ENOUGH_MEMORY) {
                    throw new IllegalArgumentException(
                            ErrorStrings.SES_NOT_ENOUGH_MEMORY);
                } else {
                    throw new IOException(
                            "Update process failed. Put data operation "
                                    + "failed: "
                                    + ErrorStrings.unexpectedStatusWord(e
                                            .getSwValue()));
                }
            } catch (IOException e) {
                try {
                    sendDeleteEntryCommand(id);
                    create(title, previousData);
                } catch (ProcessingException t) {
                }

                throw e;
            }

            // If everything worked, update the position
            position += buffer.length;
        }
    }

    /**
     * This command reads and returns the byte stream of a data entry stored in
     * the Secure Element referenced by the title.
     *
     * @param title the title of the entry that must already exist. The max.
     *        title length is 60. All characters must be supported by UTF-8.
     *
     * @return the data contained in the file.
     *
     * @throws SecurityException if the PIN to access the Secure Storage Applet
     *         was not verified.
     * @throws IllegalStateException if the used channel is closed.
     * @throws IllegalArgumentException if the title has bad encoding or wrong
     *         length (empty or too long).
     * @throws IOException if the entry couldn't be read because of an
     *         incomplete read procedure.
     * @throws IllegalArgumentException when there are incorrect P1 or P2.
     *         TODO: should be an IllegalReferenceError
     */
    public byte[] read(String title) throws IllegalStateException, IOException,
            IllegalArgumentException, SecurityException {

        if (title == null) {
            throw new IllegalArgumentException(ErrorStrings.paramNull("title"));
        }
        if (title.length() == 0 || title.length() > MAX_TITLE_LENGTH) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("title"));
        }

        int id;

        try {
            id = sendGetIdCommand(title);
        } catch (ProcessingException e) {
            switch (e.getSwValue()) {
            case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                throw new SecurityException(
                        ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
            case ResponseApdu.SES_SW_REF_NOT_FOUND:
                return new byte[0];
            default:
                throw new IOException(ErrorStrings.unexpectedStatusWord(
                        e.getSwValue()));
            }
        }

        try {
            sendSelectCommand(id);
        } catch (ProcessingException e) {
            switch (e.getSwValue()) {
            case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                throw new SecurityException(
                        ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
            default:
                throw new IOException(ErrorStrings.unexpectedStatusWord(
                        e.getSwValue()));
            }
        }

        byte[] data;
        int dataSize;
        int bytesRecieved = 0;

        // Get the size of the entry
        try {
            dataSize = ByteArrayConverter.byteArrayToInt(sendGetDataCommand(GetDataP1.Size));
            data = new byte[dataSize];
        } catch (ProcessingException e) {
            switch (e.getSwValue()) {
            case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                throw new SecurityException(
                        ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
            default:
                throw new IOException(ErrorStrings.unexpectedStatusWord(e
                        .getSwValue()));
            }
        }

        while (bytesRecieved < dataSize) {
            GetDataP1 p1;

            // Decide P1
            if (bytesRecieved == 0) {
                p1 = GetDataP1.First;
            } else {
                p1 = GetDataP1.Next;
            }

            // Get data and save it to byte array
            try {
                byte[] buffer = sendGetDataCommand(p1);
                System.arraycopy(buffer, 0, data, bytesRecieved, buffer.length);
                bytesRecieved += buffer.length;
            } catch (ProcessingException e) {
                switch (e.getSwValue()) {
                case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                    throw new SecurityException(
                            ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
                default:
                    throw new IOException(ErrorStrings.unexpectedStatusWord(e
                            .getSwValue()));
                }
            }
        }

        return data;
    }

    /**
     * This command checks if the Secure Storage entry with the defined title
     * exists.
     *
     * @param title the title of the entry that shall be checked. The max. title
     *        length is 60. All characters must be supported by UTF-8.
     *
     * @return True if the entry with the defined title exists. False if the
     *         entry does not exist.
     *
     * @throws IllegalStateException if the used channel is closed.
     * @throws IllegalArgumentException if the title is incorrect: bad encoding
     *         or wrong length (empty or too long).
     * @throws SecurityException if the PIN to access the Secure Storage Applet
     *         was not verified.
     * @throws IOException lower-level API exception.
     */
    public boolean exist(String title) throws IllegalStateException,
            IllegalArgumentException, SecurityException, IOException {

        if (title == null) {
            throw new IllegalArgumentException(ErrorStrings.paramNull("title"));
        }
        if (title.length() == 0) {
            throw new IllegalArgumentException(ErrorStrings.SES_EMPTY_TITLE);
        }
        if (title.length() > MAX_TITLE_LENGTH) {
            throw new IllegalArgumentException(ErrorStrings.SES_LONG_TITLE);
        }

        try {
            sendGetIdCommand(title);
            return true;
        } catch (ProcessingException e) {
            switch (e.getSwValue()) {
            case ResponseApdu.SES_SW_REF_NOT_FOUND:
                return false;
            case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                throw new SecurityException(
                        ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
            default:
                throw new IOException(ErrorStrings.unexpectedStatusWord(e
                        .getSwValue()));
            }
        }
    }

    /**
     * This command deletes the Secure Storage entry referenced by the title. If
     * the entry does not exist nothing will be done.
     *
     * @param title The title of the entry that must already exist. The max.
     *        title length is 60. All characters must be supported by UTF-8.
     *
     * @return True if the entry with the defined title is deleted. False if the
     *         entry does not exist.
     *
     * @throws IllegalStateException if the used channel is closed.
     * @throws IllegalArgumentException if the title is incorrect: bad encoding
     *         or wrong length (empty or too long).
     * @throws IOException if there is an error in the transport layer.
     * @throws SecurityException if old PIN to access the Secure Storage Applet
     *         was not verified.
     */
    public boolean delete(String title) throws IllegalStateException,
            IllegalArgumentException, IOException, SecurityException {

        if (title == null) {
            throw new IllegalArgumentException(ErrorStrings.paramNull("title"));
        }
        if (title.length() == 0) {
            throw new IllegalArgumentException(ErrorStrings.SES_EMPTY_TITLE);
        }
        if (title.length() > MAX_TITLE_LENGTH) {
            throw new IllegalArgumentException(ErrorStrings.SES_LONG_TITLE);
        }

        int id;
        try {
            id = sendGetIdCommand(title);
        } catch (ProcessingException e) {
            switch (e.getSwValue()) {
            case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                throw new SecurityException(
                        ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
            case ResponseApdu.SES_SW_REF_NOT_FOUND:
                return false;
            default:
                throw new IOException(ErrorStrings.unexpectedStatusWord(e
                        .getSwValue()));
            }
        }

        try {
            return sendDeleteEntryCommand(id);
        } catch (ProcessingException e) {
            switch (e.getSwValue()) {
            case ResponseApdu.SES_SW_MEMORY_FAILURE:
                throw new IOException(ErrorStrings.MEMORY_FAILURE);
            case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                throw new SecurityException(
                        ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
            default:
                throw new IOException(
                        ErrorStrings.unexpectedStatusWord(e.getSwValue()));
            }
        }
    }

    /**
     * This command deletes all Secure Storage entry referenced. If no entries
     * exist, nothing will be done
     *
     * @throws SecurityException if the PIN to access the Secure Storage Applet
     *         was not verified.
     * @throws IllegalStateException if the used channel is closed.
     * @throws IOException if there is an error in the transport layer.
     */
    public void deleteAll() throws IllegalStateException, SecurityException,
            IOException {

        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_PROPRIETARY);
        apdu.setIns(CommandApdu.INS_DELETE_ALL_SS_ENTRIES);
        apdu.setP1((byte) 0x00);
        apdu.setP2((byte) 0x00);
        byte[] apduResponse = apdu.sendApdu();

        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            return;
        case ResponseApdu.SES_SW_MEMORY_FAILURE:
            throw new IOException(ErrorStrings.MEMORY_FAILURE);
        case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        default:
            throw new IOException(ErrorStrings.unexpectedStatusWord(swValue));
        }
    }

    /**
     * This command returns an entry list with all title-identifier. The title
     * is intended for the users to identify and to reference the Secure Storage
     * entries.
     *
     * @return a list of all entries located in Secure Storage. An empty list
     *         will be returned if no entries exist in the Secure Storage
     *
     * @throws SecurityException if the PIN to access the Secure Storage Applet
     *         was not verified.
     * @throws IllegalStateException if the used channel is closed.
     * @throws IOException if there is an error in the transport layer.
     */
    public String[] list() throws IllegalStateException, SecurityException,
            IOException {

        // The list that will store the titles
        ArrayList<String> titles = new ArrayList<String>();

        boolean allEntriesHasBeenRead = false;

        // Read the first entry
        try {
            titles.add(sendSelectCommand(SelectP1.First));
        } catch (ProcessingException e) {
            switch (e.getSwValue()) {
            case ResponseApdu.SES_SW_REF_NOT_FOUND:
                // There are no more entries.
                allEntriesHasBeenRead = true;
            case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                throw new SecurityException(
                        ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
            default:
                throw new IOException(ErrorStrings.unexpectedStatusWord(e
                        .getSwValue()));
            }
        }

        // Read the next entries
        while (!allEntriesHasBeenRead) {
            try {
                titles.add(sendSelectCommand(SelectP1.Next));
            } catch (ProcessingException e) {
                switch (e.getSwValue()) {
                case ResponseApdu.SES_SW_REF_NOT_FOUND:
                    // There are no more entries.
                    allEntriesHasBeenRead = true;
                    break;
                case ResponseApdu.SES_SW_SECURITY_STATUS_NOT_SATISFIED:
                    throw new SecurityException(
                            ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
                default:
                    throw new IOException(ErrorStrings.unexpectedStatusWord(e
                            .getSwValue()));
                }
            }
        }

        return (String[]) titles.toArray(new String[titles.size()]);
    }

    /* **************************************************************** */
    /* Private methods and fields                                       */
    /* **************************************************************** */

    /**
     * Values for P1 field in a SELECT command.
     */
    private enum SelectP1 {
        /**
         * Select by ID.
         */
        Id,
        /**
         * Select first entry.
         */
        First,
        /**
         * Select next entry.
         */
        Next
    }

    /**
     * Values for P1 field in a PUT DATA command.
     */
    private enum PutDataP1 {
        /**
         * Data field contains the size of the data that shall be stored.
         */
        Size,
        /**
         * Data field contains the first data part.
         */
        First,
        /**
         * Data field contains the next data part.
         */
        Next
    }

    /**
     * Values for P1 field in a GET DATA command.
     */
    private enum GetDataP1 {
        /**
         * Response contains the whole size of the data to be read.
         */
        Size,
        /**
         * Response contains the first data part.
         */
        First,
        /**
         * Response contains the next data part.
         */
        Next
    }

    /**
     * Sends a SeS PING command.
     *
     * @return true if the response is 0x9000, false otherwise.
     */
    private boolean sendPingCommand() {
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_PROPRIETARY);
        apdu.setIns(CommandApdu.INS_PING_SS_APPLET);
        apdu.setP1((byte) 0x00);
        apdu.setP2((byte) 0x00);
        try {
            byte[] response = apdu.sendApdu();
            return ResponseApdu.getResponseStatusWordValue(response)
                    == ResponseApdu.SW_NO_FURTHER_QUALIFICATION;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Sends a SeS CREATE ENTRY command.
     *
     * @param title The title of the SeS entry to be created.
     *
     * @return The ID of the new entry.
     *
     * @throws IOException lower-level API exception.
     * @throws ProcessingException when SW != 0x9000.
     */
    private int sendCreateEntryCommand(String title) throws IOException,
            ProcessingException {

        byte[] titleArray = title.getBytes();
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_PROPRIETARY);
        apdu.setIns(CommandApdu.INS_CREATE_SS_ENTRY);
        apdu.setP1((byte) 0x00);
        apdu.setP2((byte) 0x00);
        apdu.setData(titleArray);

        byte[] apduResponse = apdu.sendApdu();
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        if (swValue == ResponseApdu.SW_NO_FURTHER_QUALIFICATION) {
            return ByteArrayConverter.byteArrayToInt(ResponseApdu
                    .getResponseData(apduResponse));
        } else {
            throw new ProcessingException(swValue);
        }
    }

    /**
     * Sends a SeS DELETE ENTRY command.
     *
     * @param id The ID of the entry to be deleted.
     *
     * @return true if the entry was deleted, false if it didn't exist.
     *
     * @throws IOException lower-level API exception.
     * @throws ProcessingException when SW != 0x9000.
     */
    private boolean sendDeleteEntryCommand(int id)
            throws IOException, ProcessingException {

        byte[] idArray = ByteArrayConverter.intToByteArray(id);
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_PROPRIETARY);
        apdu.setIns(CommandApdu.INS_DELETE_SS_ENTRY);
        apdu.setP1(idArray[0]);
        apdu.setP2(idArray[1]);

        byte[] apduResponse = apdu.sendApdu();
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        if (swValue == ResponseApdu.SW_NO_FURTHER_QUALIFICATION) {
            return true;
        } else if (swValue == ResponseApdu.SES_SW_REF_NOT_FOUND) {
            return false;
        } else {
            throw new ProcessingException(swValue);
        }
    }

    /**
     * Sends a SeS SELECT ENRTY command.
     *
     * @param p1 The value of the P1 field on the APDU to be sent.
     * @param id The ID of the entry to be selected (Only if p1 = SelectP1.ID).
     *
     * @return The title of the selected entry.
     *
     * @throws IOException lower-level API exception.
     * @throws ProcessingException when SW != 0x9000.
     */
    private String sendSelectCommand(SelectP1 p1, int id)
            throws IOException, ProcessingException {

        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_PROPRIETARY);
        apdu.setIns(CommandApdu.INS_SELECT_SS_ENTRY);
        switch(p1) {
        case Id:
            apdu.setP1((byte) 0x00);
            byte[] idByteArray = new byte[2];
            System.arraycopy(
                    ByteArrayConverter.intToByteArray(id),
                    2,
                    idByteArray,
                    0,
                    2);
            apdu.setData(idByteArray);
            break;
        case First:
            apdu.setP1((byte) 0x01);
            break;
        case Next:
            apdu.setP1((byte) 0x02);
            break;
        }
        apdu.setP2((byte) 0x00);
        apdu.setLE((byte) 0x00);
        byte[] apduResponse = apdu.sendApdu();
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        if (swValue == ResponseApdu.SW_NO_FURTHER_QUALIFICATION) {
            return ByteArrayConverter.byteArrayToCharString(ResponseApdu
                    .getResponseData(apduResponse));
        } else {
            throw new ProcessingException(swValue);
        }
    }

    /**
     * Sends a SeS SELECT ENRTY command.
     *
     * @param p1 The value of the P1 field on the APDU to be sent.
     *
     * @return The title of the selected entry.
     *
     * @throws IOException
     *
     * @throws IOException lower-level API exception.
     * @throws ProcessingException when SW != 0x9000.
     * @throws IllegalArgumentException If P1 = SelectP1.Id is used.
     */
    private String sendSelectCommand(SelectP1 p1) throws
        IOException, ProcessingException, IllegalArgumentException {
        if (p1 == SelectP1.Id) {
            throw new IllegalArgumentException();
        }
        return sendSelectCommand(p1, 0);
    }

    /**
     * Sends a SeS SELECT ENRTY command.
     *
     * @param id The ID of the entry to be selected.
     *
     * @return The title of the selected entry.
     *
     * @throws IOException lower-level API exception.
     * @throws ProcessingException when SW != 0x9000.
     */
    private String sendSelectCommand(int id)
            throws IOException, ProcessingException {
        return sendSelectCommand(SelectP1.Id, id);
    }

    /**
     * Sends a SeS PUT DATA command.
     *
     * @param p1 The value for the P1 field.
     * @param data The data to be written.
     *
     * @throws IOException lower-level API exception.
     * @throws ProcessingException when SW != 0x9000.
     */
    private void sendPutDataCommand(PutDataP1 p1, byte[] data)
            throws IOException, ProcessingException {

        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_PROPRIETARY);
        apdu.setIns(CommandApdu.INS_PUT_SS_ENTRY_DATA);
        switch(p1) {
        case Size:
            apdu.setP1((byte) 0x00);
            break;
        case First:
            apdu.setP1((byte) 0x01);
            break;
        case Next:
            apdu.setP1((byte) 0x02);
            break;
        }
        apdu.setP2((byte) 0x00);
        apdu.setData(data);
        byte[] apduResponse = apdu.sendApdu();
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        if (swValue != ResponseApdu.SW_NO_FURTHER_QUALIFICATION) {
            throw new ProcessingException(swValue);
        }
    }

    /**
     * Sends a SeS PUT DATA command with P1 = PutDataP1.Size.
     *
     * @param dataSize the size of the data.
     *
     * @throws IOException lower-level API exception.
     * @throws ProcessingException when SW != 0x9000.
     */
    private void sendPutDataCommand(int dataSize)
        throws IOException, ProcessingException {
        byte[] baDataSize = new byte[2];
        System.arraycopy(
                ByteArrayConverter.intToByteArray(dataSize),
                2,
                baDataSize,
                0,
                2);
        sendPutDataCommand(PutDataP1.Size, baDataSize);
    }

    /**
     * Sends a SeS GET DATA command.
     *
     * @param p1 The value for the P1 field.
     *
     * @return the data of the currently selected SeS entry.
     *
     * @throws IOException lower-level API exception.
     * @throws ProcessingException when SW != 0x9000.
     */
    private byte[] sendGetDataCommand(GetDataP1 p1)
            throws IOException, ProcessingException {

        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_PROPRIETARY);
        apdu.setIns(CommandApdu.INS_GET_SS_ENTRY_DATA);
        switch(p1) {
        case Size:
            apdu.setP1((byte) 0x00);
            break;
        case First:
            apdu.setP1((byte) 0x01);
            break;
        case Next:
            apdu.setP1((byte) 0x02);
            break;
        }
        apdu.setP2((byte) 0x00);
        apdu.setLE((byte) 0x00);
        byte[] apduResponse = apdu.sendApdu();
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        if (swValue == ResponseApdu.SW_NO_FURTHER_QUALIFICATION) {
            return ResponseApdu.getResponseData(apduResponse);
        } else {
            throw new ProcessingException(swValue);
        }
    }

    /**
     * Sends a SeS GET ID command.
     *
     * @param title The title of the entry.
     *
     * @return The ID of the specified entry.
     *
     * @throws IOException lower-level API exception.
     * @throws ProcessingException when SW != 0x9000.
     */
    private int sendGetIdCommand(String title)
            throws IOException, ProcessingException {

        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_PROPRIETARY);
        apdu.setIns(CommandApdu.INS_READ_RECORD_B2);
        apdu.setP1((byte) 0x00);
        apdu.setP2((byte) 0x00);
        apdu.setData(title.getBytes());

        byte[] apduResponse = apdu.sendApdu();
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        if (swValue == ResponseApdu.SW_NO_FURTHER_QUALIFICATION) {
            return ByteArrayConverter.byteArrayToInt(ResponseApdu
                    .getResponseData(apduResponse));
        } else {
            throw new ProcessingException(swValue);
        }
    }



    /**
     * Exception that wraps "non-9000" response.
     */
    private class ProcessingException extends Exception {

        /**
         * Status word value.
         */
        private int mSwValue;

        /**
         * Constructor.
         *
         * @param swValue The value of the Status Word.
         */
        private ProcessingException(int swValue) {
            mSwValue = swValue;
        }

        /**
         * Returns the value of the Status Word.
         *
         * @return the status word value.
         */
        private int getSwValue() {
            return mSwValue;
        }
    }
}
