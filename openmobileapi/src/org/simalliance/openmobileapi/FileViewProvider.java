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

import org.simalliance.openmobileapi.internal.BerTlvParser;
import org.simalliance.openmobileapi.internal.ByteArrayConverter;
import org.simalliance.openmobileapi.internal.ErrorStrings;
import org.simalliance.openmobileapi.internal.TlvEntryWrapper;
import org.simalliance.openmobileapi.util.CommandApdu;
import org.simalliance.openmobileapi.util.ResponseApdu;

/**
 * This Provider class simplifies file operations on Secure Elements with a file
 * structure specified in ISO/IEC 7816-4. Methods are provided that allow
 * reading or writing file content. If the read or write operation is not
 * allowed because security conditions are not satisfied a SecurityException
 * will be returned. It must be considered that a file operation can only be
 * applied onto a file which has a corresponding structure.
 * <p>
 * <b>Prerequisites:</b> This Provider requires an ISO/IEC 7816-4 compliant file
 * system on the SE. If this file system is implemented by an Applet within the
 * SE then this Applet must be preselected before this Provider can be used, in
 * case that the Applet is not default selected (e.g. the GSM Applet as default
 * selected Applet on UICC)
 * <p>
 * <b>Notes:</b>
 * <ul>
 * <li>If used by multiple threads, synchronization is up to the application.</li>
 * <li>Each operation needs an access to the Secure Element. If the access can
 * not be granted because of a closed channel or a missing security condition
 * the called method will return an error.</li>
 * <li>Using the basic channel for accessing the file system of the UICC
 * (provided by the default selected GSM Applet) implies the risk of
 * interferences from the baseband controller as the baseband controller works
 * internally on the basic channel and can modify the current file selected
 * state on the basic channel any time. This means a file selection performed by
 * this FileViewProvider does not guarantee a permanent file selection state on
 * the ICC's basic channel and the application using the FileViewProvider has to
 * take care of having the needed file selection state. The FileViewProvider
 * itself cannot avoid interferences from the baseband Open Mobile API
 * specification V2.0.2 29/63 controller on the basic channel but the risk could
 * be minimized if the application using the FileViewProvider performs implicit
 * selections for the file operation or performs the file selection immediately
 * before the file operation.</li>
 * </ul>
 */
public class FileViewProvider extends Provider {

    /**
     * Indicates for file operation methods that the currently selected file
     * shall be used for the file operation.
     */
    public static final int CURRENT_FILE = 0;

    /**
     * Indicates that the demanded information is not available.
     */
    public static final int INFO_NOT_AVAILABLE = -1;

    /**
     * Indicates for record write operations that the record shell be appended.
     */
    public static final int APPEND_RECORD = -1;

    /**
     * The number of digits that should form a File ID.
     */
    private static final int FILE_ID_LENGTH = 4;

    /**
     * The minimum value for a short EF identifier.
     */
    private static final int SFI_MIN_VALUE = 1;

    /**
     * The maximum value for a short EF identifier.
     */
    private static final int SFI_MAX_VALUE = 30;

    /**
     * The minimum value for a record number.
     */
    private static final int REC_NUMBER_MIN_VALUE = 0x00;

    /**
     * The maximum value for a record number.
     */
    private static final int REC_NUMBER_MAX_VALUE = 0xFE;

    /**
     * The maximum value of a long offset.
     */
    private static final int OFFSET_LONG_MAX_VALUE = 0x7FFF;

    /**
     * The maximum value of a short offset.
     */
    private static final int OFFSET_SHORT_MAX_VALUE = 0xFF;

    /**
     * The minimum value for a File ID.
     */
    private static final int FID_MIN_VALUE = 0x0001;

    /**
     * The maximum value for a File ID.
     */
    private static final int FID_MAX_VALUE = 0xFFFE;

    /**
     * The byte length of a File ID.
     */
    private static final int FID_LENGTH = 0x02;

    /**
     * File Control Parameter contain information of a selected file. FCPs are
     * returned after a file select operation.
     * <p>
     * <b>Note:</b> This class is based on ISO/IEC 7816-4 FCP returned by the
     * SELECT command as specified in ISO/IEC 7816-4 in chapter 5.3.3 (File
     * control information) in table 12 (File control parameter data objects).
     */
    public class FCP {

        // FCP tags.
        /**
         * FCP template TLV tag.
         */
        public static final byte FCPTAG_FCP_TEMPLATE = (byte) 0x62;
        /**
         * FCP file size TLV tag.
         */
        public static final byte FCPTAG_FILE_SIZE = (byte) 0x80;
        /**
         * FCP total file size TLV tag.
         */
        public static final byte FCPTAG_TOTAL_FILE_SIZE = (byte) 0x81;
        /**
         * FCP file descriptor TLV tag.
         */
        public static final byte FCPTAG_FILE_DESCRIPTOR = (byte) 0x82;
        /**
         * FCP file ID TLV tag.
         */
        public static final byte FCPTAG_FILE_ID = (byte) 0x83;
        /**
         * FCP ShortFileIdentifier TLV tag.
         */
        public static final byte FCPTAG_SFI = (byte) 0x88;
        /**
         * FCP Life Cycle Status TLV tag.
         */
        public static final byte FCPTAG_LCS = (byte) 0x8A;

        // File types.
        /**
         * File type = DF.
         */
        public static final byte FILETYPE_DF = 0;
        /**
         * File type = EF.
         */
        public static final byte FILETYPE_EF = 1;

        // FileStructure types.
        /**
         * EF structure: No information given.
         */
        public static final int FILESTRUCTURE_NO_EF = 0;
        /**
         * EF structure: Transparent structure.
         */
        public static final int FILESTRUCTURE_TRANSPARENT = 1;
        /**
         * EF structure: Linear structure, fixed size.
         */
        public static final int FILESTRUCTURE_LINEAR_FIXED = 2;
        /**
         * EF structure: Linear structure, variable size.
         */
        public static final int FILESTRUCTURE_LINEAR_VARIABLE = 3;
        /**
         * EF structure: Cyclic structure, fixed size.
         */
        public static final int FILESTRUCTURE_CYCLIC = 4;

        // LCS values.
        /**
         * Life Cycle Status: No information given.
         */
        public static final int LCS_NO_INFORMATION_GIVEN = 0;
        /**
         * Life Cycle Status: Creation state.
         */
        public static final int LCS_CREATION_STATE = 1;
        /**
         * Life Cycle Status: Initialization state.
         */
        public static final int LCS_INITIALISATION_STATE = 2;
        /**
         * Life Cycle Status: Operational state (activated).
         */
        public static final int LCS_OPERATIONAL_STATE_ACTIVATED = 3;
        /**
         * Life Cycle Status: Operational state (deactivated).
         */
        public static final int LCS_OPERATIONAL_STATE_DEACTIVATED = 4;
        /**
         * Life Cycle Status: Termination state.
         */
        public static final int LCS_TERMINATION_STATE = 5;

        /**
         * The complete FCP data as byte array.
         */
        private byte[] mRawFcpData;

        /**
         * Initializes a new instance of the FCP class.
         *
         * @param rawTlvData The data to be used in the initialization.
         *
         * @throws IllegalArgumentException if the specified rawTlvData does not
         *         contain valid FCP data.
         */
        public FCP(byte[] rawTlvData) throws IllegalArgumentException {
            // Find and get the FCP data
            BerTlvParser parser = new BerTlvParser();
            int fcpStartPosition = parser.searchTag(
                    rawTlvData, new byte[] {FCPTAG_FCP_TEMPLATE}, 0);
            mRawFcpData = new TlvEntryWrapper(
                    rawTlvData,
                    fcpStartPosition,
                    parser)
                .getValue();
        }

        /**
         * Returns the complete FCP as byte array.
         * <p>
         * <b>Note:</b> This method is based on the FCP control parameter as
         * specified in ISO/IEC 7816-4 in chapter 5.3.3 (File control
         * information) in table 12 (File control parameter data objects).
         *
         * @return The complete FCP as byte array.
         */
        public byte[] getFCP() {
            return mRawFcpData;
        }

        /**
         * Returns the file size of the selected file (Number of data bytes in
         * the file, excluding structural information).
         * <p>
         * <b>Note:</b> This method is based on the FCP control parameter as
         * specified in ISO/IEC 7816-4 in chapter 5.3.3 (File control
         * information) in table 12 (File control parameter data objects).
         *
         * @return The file size depending on the file type:
         *         <ul>
         *         <li>DF/MF: the total file size represents the sum of the file
         *         sizes of all the EFs and DFs contained in this DF plus the
         *         amount of available memory in this DF. The size of the
         *         structural information of the selected DF itself is not
         *         included.</li> <li>EF: the total file size represents the
         *         allocated memory for the content and the structural
         *         information (if any) of this EF.</li>
         *         </ul>
         *         <p>
         *         INFO_NOT_AVAILABLE if the information is not available.
         */
        public int getFileSize() {
            BerTlvParser parser = new BerTlvParser();
            try {
                int position = parser.searchTag(
                        mRawFcpData, new byte[] {FCPTAG_FILE_SIZE}, 0);
                byte[] fileSize = new TlvEntryWrapper(
                        mRawFcpData, position, parser).getValue();
                return ByteArrayConverter.byteArrayToInt(fileSize);
            } catch (IllegalArgumentException e) {
                return INFO_NOT_AVAILABLE;
            }
        }

        /**
         * Returns the total file size of the selected file (Number of data
         * bytes in the file, including structural information if any).
         * <p>
         * <b>Note:</b> This method is based on the FCP control parameter as
         * specified in ISO/IEC 7816-4 in chapter 5.3.3 (File control
         * information) in table 12 (File control parameter data objects).
         *
         * @return The total file size depending on the file type:
         *         <ul>
         *         <li>DF/MF: the total file size represents the sum of the file
         *         sizes of all the EFs and DFs contained in this DF plus the
         *         amount of available memory in this DF. The size of the
         *         structural information of the selected DF itself is not
         *         included. </li> <li>EF: the total file size represents the
         *         allocated memory for the content and the structural
         *         information (if any) of this EF.</li>
         *         </ul>
         *         INFO_NOT_AVAILABLE if the information is not available.
         */
        public int getTotalFileSize() {
            BerTlvParser parser = new BerTlvParser();
            try {
                int position = parser.searchTag(
                        mRawFcpData, new byte[] {FCPTAG_TOTAL_FILE_SIZE}, 0);
                byte[] totalFileSize = new TlvEntryWrapper(
                        mRawFcpData, position, parser).getValue();
                return ByteArrayConverter.byteArrayToInt(totalFileSize);
            } catch (IllegalArgumentException e) {
                return INFO_NOT_AVAILABLE;
            }
        }

        /**
         * Returns the file identifier of the selected file.
         * <p>
         * <b>Note:</b> This method is based on the FCP control parameter as
         * specified in ISO/IEC 7816-4 in chapter 5.3.3 (File control
         * information) in table 12 (File control parameter data objects).
         *
         * @return The file identifier of the selected file. INFO_NOT_AVAILABLE
         *         if the FID of the selected file is not available.
         */
        public int getFID() {
            BerTlvParser parser = new BerTlvParser();
            try {
                int position = parser.searchTag(
                        mRawFcpData, new byte[] {FCPTAG_FILE_ID}, 0);
                byte[] fileId = new TlvEntryWrapper(
                        mRawFcpData, position, parser).getValue();
                return ByteArrayConverter.byteArrayToInt(fileId);
            } catch (IllegalArgumentException e) {
                return INFO_NOT_AVAILABLE;
            }
        }

        /**
         * Returns the short file identifier of the selected EF file.
         * <p>
         * <b>Note:</b> This method is based on the FCP control parameter as
         * specified in ISO/IEC 7816-4 in chapter 5.3.3 (File control
         * information) in table 12 (File control parameter data objects).
         *
         * @return The short file identifier of the selected file.
         *         INFO_NOT_AVAILABLE if selected file is not an EF or an SFI is
         *         not available.
         */
        public int getSFI() {
            BerTlvParser parser = new BerTlvParser();
            try {
                int position = parser.searchTag(
                        mRawFcpData, new byte[] {FCPTAG_SFI}, 0);
                byte[] sfi = new TlvEntryWrapper(
                        mRawFcpData, position, parser).getValue();

                // If FCPTAG_SFI is present, there are two possibilities:
                if (sfi.length == 0) {
                    // If the value length is 0, selection by SFI is not
                    // supported
                    return INFO_NOT_AVAILABLE;
                } else if (sfi.length == 1) {
                    // From ISO/IEC 7816-9 5.3.3.1
                    // If tag '88' is present with a length set to one and
                    // if bits 8 to 4 of the data element are not all equal and
                    // if bits 3 to 1 are set to 000, then bits 8 to 4 encode
                    // the short EF identifier (a number from one to thirty).
                    if ((sfi[0] & (byte) 0x07) == (byte) 0x00) {
                        // Shift 3 bits to the right
                        return (int) (sfi[0] >>> 3);
                    } else {
                        return INFO_NOT_AVAILABLE;
                    }
                } else {
                    return INFO_NOT_AVAILABLE;
                }
            }  catch (IllegalArgumentException e) {
                // If FCPTAG_SFI is not present, there might be two reasons:
                // 1) If card supports selection by SFI, the bits 5 to 1 of FID
                // encode the SFI
                // TODO: implement this case

                // 2) Card might no support selection by SFI
                return INFO_NOT_AVAILABLE;
            }
        }

        /**
         * Returns the maximum record size in case of a record based EF.
         * <p>
         * <b>Note:</b> This method is based on the FCP control parameter as
         * specified in ISO/IEC 7816-4 in chapter 5.3.3 (File control
         * information) in table 12 (File control parameter data objects).
         *
         * @return The maximum record size in case of a record based EF.
         *         INFO_NOT_AVAILABLE if the currently selected file is not
         *         record based or the information can not be fetched.
         */
        public int getMaxRecordSize() {
            BerTlvParser parser = new BerTlvParser();
            try {
                int position = parser.searchTag(
                        mRawFcpData, new byte[] {FCPTAG_FILE_DESCRIPTOR}, 0);
                byte[] fileDescriptor = new TlvEntryWrapper(
                        mRawFcpData, position, parser).getValue();
                if (fileDescriptor.length < 3) {
                    // No MaxRecordSize
                    return INFO_NOT_AVAILABLE;
                } else {
                    byte[] maxRecSize;
                    if (fileDescriptor.length == 3) {
                        maxRecSize = new byte[1];
                    } else {
                        maxRecSize = new byte[2];
                    }

                    System.arraycopy(fileDescriptor, 2, maxRecSize, 0,
                            maxRecSize.length);
                    return ByteArrayConverter.byteArrayToInt(maxRecSize);
                }
            } catch (IllegalArgumentException e) {
                return INFO_NOT_AVAILABLE;
            }
        }

        /**
         * Returns the number of records stored in the EF in case of a record
         * based EF.
         * <p>
         * <b>Note:</b> This method is based on the FCP control parameter as
         * specified in ISO/IEC 7816-4 in chapter 5.3.3 (File control
         * information) in table 12 (File control parameter data objects).
         *
         * @return The number of records stored in the EF in case of a record
         *         based EF. INFO_NOT_AVAILABLE if the currently selected file
         *         is not record based or the information can not be fetched.
         */
        public int getNumberOfRecords() {
            BerTlvParser parser = new BerTlvParser();
            try {
                int position = parser.searchTag(
                        mRawFcpData, new byte[] {FCPTAG_FILE_DESCRIPTOR}, 0);
                byte[] fileDescriptor = new TlvEntryWrapper(
                        mRawFcpData, position, parser).getValue();

                if (fileDescriptor.length < 5) {
                    return INFO_NOT_AVAILABLE;
                } else {
                    byte[] numberOfRecords;
                    if (fileDescriptor.length == 5) {
                        numberOfRecords = new byte[1];
                    } else {
                        numberOfRecords = new byte[2];
                    }

                    System.arraycopy(fileDescriptor, 4, numberOfRecords, 0,
                            numberOfRecords.length);
                    return ByteArrayConverter.byteArrayToInt(numberOfRecords);
                }
            } catch (IllegalArgumentException e) {
                return INFO_NOT_AVAILABLE;
            }
        }

        /**
         * Returns the file type of the currently selected file.
         * <p>
         * <b>Note: </b> This method is based on the FCP control parameter as
         * specified in ISO/IEC 7816-4 in chapter 5.3.3 (File control
         * information) in table 12 (File control parameter data objects). The
         * file type is based on the definition in table 14 (File descriptor
         * byte).
         *
         * @return The file type:
         *         <ul>
         *         <li>(0) DF</li> <li>(1) EF</li>
         *         </ul>
         *         INFO_NOT_AVAILABLE if the information can not be fetched.
         */
        public int getFileType() {
            BerTlvParser parser = new BerTlvParser();
            try {
                int position = parser.searchTag(
                        mRawFcpData, new byte[] {FCPTAG_FILE_DESCRIPTOR}, 0);
                byte[] fileDescriptor = new TlvEntryWrapper(
                        mRawFcpData, position, parser).getValue();

                // Mask interesting bits to decide if file type is DF.
                boolean isDf = ((fileDescriptor[0] & 0xBF) == 0x38);

                if (isDf) {
                    return FILETYPE_DF;
                } else {
                    return FILETYPE_EF;
                }
            } catch (IllegalArgumentException e) {
                return INFO_NOT_AVAILABLE;
            }
        }

        /**
         * Returns the structure type of the selected EF.
         * <p>
         * <b>Note:</b> This method is based on the FCP control parameter as
         * specified in ISO/IEC 7816-4 in chapter 5.3.3 (File control
         * information) in table 12 (File control parameter data objects). The
         * file type is based on the definition in table 14 (File descriptor
         * byte).
         *
         * @return The structure type of the selected file:
         *         <ul>
         *         <li>(0) NO_EF</li> <li>(1) TRANSPARENT</li> <li>(2)
         *         LINEAR_FIXED</li> <li>(3) LINEAR_VARIABLE</li> <li>(4) CYCLIC
         *         </li>
         *         </ul>
         *         INFO_NOT_AVAILABLE if the information can not be fetched.
         */
        public int getFileStructure() {
            BerTlvParser parser = new BerTlvParser();
            try {
                int position = parser.searchTag(
                        mRawFcpData, new byte[] {FCPTAG_FILE_DESCRIPTOR}, 0);
                byte[] fileDescriptor = new TlvEntryWrapper(
                        mRawFcpData, position, parser).getValue();

                switch (fileDescriptor[0] & 0x07) {
                case 0:
                    return FILESTRUCTURE_NO_EF;
                case 1:
                    return FILESTRUCTURE_TRANSPARENT;
                case 2:
                case 3:
                    return FILESTRUCTURE_LINEAR_FIXED;
                case 4:
                case 5:
                    return FILESTRUCTURE_LINEAR_VARIABLE;
                case 6:
                case 7:
                    return FILESTRUCTURE_CYCLIC;
                default:
                    return INFO_NOT_AVAILABLE;
                }
            } catch (IllegalArgumentException e) {
                return INFO_NOT_AVAILABLE;
            }
        }

        /**
         * Returns the life cycle state of the currently selected file.
         * <p>
         * <b>Note:</b> This method is based on the FCP control parameter as
         * specified in ISO/IEC 7816-4 in chapter 5.3.3 (File control
         * information) in table 12 (File control parameter data objects). The
         * LCS is based on the definition in table 13 (Life cycle status byte).
         *
         * @return Returns the life cycle state of the currently selected file.
         *         <ul>
         *         <li>(0) NO_INFORMATION_GIVEN</li> <li>(1) CREATION_STATE</li>
         *         <li>(2) INITIALISATION_STATE</li> <li>(3)
         *         OPERATIONAL_STATE_ACTIVATED</li> <li>(4)
         *         OPERATIONAL_STATE_DEACTIVATED</li> <li>(5) TERMINATION_STATE
         *         </li>
         *         </ul>
         *         INFO_NOT_AVAILABLE if the information can not be fetched.
         */
        public int getLCS() {
            BerTlvParser parser = new BerTlvParser();
            try {
                int position = parser.searchTag(
                        mRawFcpData, new byte[] {FCPTAG_LCS}, 0);
                byte[] lcs = new TlvEntryWrapper(
                        mRawFcpData, position, parser).getValue();

                switch (lcs[0]) {
                case 0:
                    return LCS_NO_INFORMATION_GIVEN;
                case 1:
                    return LCS_CREATION_STATE;
                case 3:
                    return LCS_INITIALISATION_STATE;
                case 5:
                case 7:
                    return LCS_OPERATIONAL_STATE_ACTIVATED;
                case 4:
                case 6:
                    return LCS_OPERATIONAL_STATE_DEACTIVATED;
                case 12:
                case 13:
                case 14:
                case 15:
                    return LCS_TERMINATION_STATE;
                default:
                    return INFO_NOT_AVAILABLE;
                }
            } catch (IllegalArgumentException e) {
                return INFO_NOT_AVAILABLE;
            }
        }
    }

    /**
     * Record class serves as container for record data. The created Record (as
     * immutable object) can be used to read record data from a file or to write
     * record data to a file.
     */
    public class Record {

        /**
         * The number of this record.
         */
        private int mNumber;

        /**
         * The data of this record.
         */
        private byte[] mData;

        /**
         * Creates a Record instance which can be used to store record data.
         *
         * @param number The record number that shall be stored.
         * @param data The data that shall be stored.
         *
         * @throws IllegalArgumentException if the defined record ID is invalid
         *         or if the data is too long.
         */
        public Record(int number, byte[] data) throws IllegalArgumentException {

            if (!(REC_NUMBER_MIN_VALUE <= number
                    && number <= REC_NUMBER_MAX_VALUE)
                    && !(number == APPEND_RECORD)) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidValue("number"));
            }

            if (data == null) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramNull("data"));
            }

            if (data.length == 0 || data.length > CommandApdu.MAX_DATA_LENGTH) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidArrayLength("data"));
            }

            mNumber = number;
            mData = data;
        }

        /**
         * Returns the data of this record.
         *
         * @return The data of this record.
         */
        public byte[] getData() {
            return mData;
        }

        /**
         * Returns the record number of this record.
         *
         * @return The record number of this record.
         */
        public int getNumber() {
            return mNumber;
        }
    }

    /**
     * Encapsulates the defined channel by a FileViewProvider object that can be
     * used for performing file operations on it.
     * <p>
     * <b>Note:</b> A file must be selected before a file operation can be
     * performed. The file can be implicitly selected via a short file
     * identifier (SFI) by the file operation method itself or explicitly by
     * defining the file ID (FID) with selectByFID(int) or path with
     * selectByPath(String, boolean).
     *
     * @param channel The channel that shall be used by this Provider for file
     *        operations.
     *
     * @throws IllegalStateException if the defined channel is closed.
     */
    public FileViewProvider(Channel channel) throws IllegalStateException {
        super(channel);
    }

    /**
     * Selects the file specified by a path. The path references the Secure
     * Element file by a path (concatenation of file IDs and the order of the
     * file IDs is always in the direction "parent to child") in following
     * notation: "DF1:DF2:EF1". e.g. "0023:0034:0043". The defined path is
     * applied to the Secure Element as specified in ISO/IEC 7816-4. Note: For
     * performing read or write operations on a file the last knot in the path
     * must reference an EF that can be read or written.
     * <p>
     * <b>Note:</b>
     * <ul>
     * <li>A file must be selected before a file operation can be performed.</li>
     * <li>This method is based on the ISO/IEC 7816-4 command SELECT.</li>
     * </ul>
     *
     * @return The FCP containing information to the selected file.
     *
     * @param path The path that references a file (DF or EF) on the Secure
     *        Element. This path shall not contain the current DF or MF at the
     *        beginning of the path.
     * @param fromCurrentDF If true then the path is selected from the current
     *        DF, if false then the path is selected from the MF.
     *
     * @throws IllegalStateException if the defined channel is closed.
     * @throws IllegalArgumentException if the file couldn't be selected.
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the defined path is invalid.
     * @throws SecurityException if the operation is not allowed because the
     *         security conditions are not satisfied.
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public FCP selectByPath(String path, boolean fromCurrentDF)
            throws IllegalStateException,
            IllegalArgumentException, SecurityException,
            UnsupportedOperationException, IOException {

        if (path == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("path"));
        }

        if (path.isEmpty()) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("path"));
        }

        String[] fileId = path.split(":");
        byte[] pathByteArray = new byte[fileId.length * FILE_ID_LENGTH / 2];

        for (int i = 0; i < fileId.length; i++) {
            // Check that fileId[i] has a valid coding
            if (fileId[i].length() != FILE_ID_LENGTH) {
                throw new IllegalArgumentException(
                        "Path elements must be 4-characters long.");
            }
            int fid = Integer.parseInt(fileId[i], 16);
            if (!(FID_MIN_VALUE <= fid && fid <= FID_MAX_VALUE)
                    || fid == 0x3FFF) {
                // 3FFF is reserved
                throw new IllegalArgumentException(ErrorStrings.INVALID_FID);
            }

            // Convert to bytes and copy to pathByteArray
            System.arraycopy(ByteArrayConverter.hexStringToByteArray(fileId[i]), 0,
                    pathByteArray, i * FILE_ID_LENGTH / 2, FILE_ID_LENGTH / 2);
        }

        // Form and send the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_SELECT);
        if (fromCurrentDF) {
            apdu.setP1((byte) 0x09);
        } else {
            apdu.setP1((byte) 0x08);
        }
        apdu.setP2((byte) 0x04);
        apdu.setData(pathByteArray);
        byte[] responseApdu = apdu.sendApdu();

        // Parse the response
        int swValue = ResponseApdu.getResponseStatusWordValue(responseApdu);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            return new FCP(ResponseApdu.getResponseData(responseApdu));
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        case ResponseApdu.SW_FILE_OR_APP_NOT_FOUND:
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.FILE_NOT_FOUND);
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        default:
            throw new IOException(ErrorStrings.unexpectedStatusWord(swValue));
        }
    }

    /**
     * Selects the file specified by the FID. The file ID references the Secure
     * Element file (DF or EF) by a FID. The FID consists of a two byte value as
     * defined in ISO/IEC 7816-4.
     * <p>
     * <b>Notes:</b>
     * <ul>
     * <li>A file must be selected before a file operation can be performed.</li>
     * <li>This method is based on the ISO/IEC 7816-4 command SELECT.</li>
     * </ul>
     *
     * @return The FCP containing information of the selected file.
     *
     * @param fileID The FID that references the file (DF or EF) on the Secure
     *        Element. The FID must be in the range of (0x0000-0xFFFF).
     *
     * @throws IllegalStateException if the defined channel is closed.
     * @throws IllegalArgumentException if the file couldn't be selected.
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the defined fileID is not valid.
     * @throws SecurityException if the operation is not allowed because the
     *         security conditions are not satisfied.
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public FCP selectByFID(int fileID) throws IllegalStateException,
            IllegalArgumentException, SecurityException,
            UnsupportedOperationException, IOException {

        // Check that fileID is in the allowed ranges
        if (!(FID_MIN_VALUE <= fileID && fileID <= FID_MAX_VALUE)
                || (fileID == 0x3FFF)) {
            // 3FFF is reserved
            throw new IllegalArgumentException(ErrorStrings.INVALID_FID);
        }

        // Form and send the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_SELECT);
        apdu.setP1((byte) 0x00);
        apdu.setP2((byte) 0x04);
        byte[] data = new byte[FID_LENGTH];
        System.arraycopy(ByteArrayConverter.intToByteArray(fileID), 2, data, 0, data.length);
        apdu.setData(data);
        byte[] responseApdu = apdu.sendApdu();

        // Parse the response
        int swValue = ResponseApdu.getResponseStatusWordValue(responseApdu);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            return new FCP(ResponseApdu.getResponseData(responseApdu));
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_WRONG_DATA:
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.FILE_NOT_FOUND);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        case ResponseApdu.SW_FILE_OR_APP_NOT_FOUND:
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.FILE_NOT_FOUND);
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        default:
            throw new IOException(ErrorStrings.unexpectedStatusWord(swValue));
        }
    }

    /**
     * Selects the parent DF of the current DF. The parent DF of the currently
     * selected file is selected according to ISO/IEC 7816-4. If the currently
     * selected file has no parent then nothing will be done.
     * <p>
     * <b>Note:</b>
     * <ul>
     * <li>A file must be selected before a file operation can be performed.</li>
     * <li>This method is based on the ISO/IEC 7816-4 command SELECT.</li>
     * </ul>
     *
     * @return The FCP containing information of the selected file.
     *
     * @throws IllegalStateException if the defined channel is closed.
     * @throws IllegalArgumentException if the file couldn't be selected.
     *         TODO: should be an IllegalReferenceError
     * @throws SecurityException if the operation is not allowed because the
     *         security conditions are not satisfied.
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public FCP selectParent() throws IllegalStateException,
            SecurityException,
            UnsupportedOperationException, IOException {

        // Form and send the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_SELECT);
        apdu.setP1((byte) 0x03);
        apdu.setP2((byte) 0x04);
        apdu.setLE((byte) 0x00);
        byte[] responseApdu = apdu.sendApdu();

        // Parse response
        int swValue = ResponseApdu.getResponseStatusWordValue(responseApdu);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            return new FCP(ResponseApdu.getResponseData(responseApdu));
        case ResponseApdu.SW_FILE_OR_APP_NOT_FOUND:
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.FILE_NOT_FOUND);
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        default:
            throw new IOException(ErrorStrings.unexpectedStatusWord(swValue));
        }
    }

    /**
     * Returns the record which corresponds to the specified record number. If
     * the record is not found then null will be returned.
     * <p>
     * <b>Note:</b> This method is based on the ISO/IEC 7816-4 command READ
     * RECORD.
     *
     * @return The record which corresponds to the specified record ID.
     *
     * @param sfi The SFI of the file which shall be selected for this read
     *        operation. CURRENT_FILE can be applied if the file is already
     *        selected. The sfi must be in the range of (1-30).
     * @param recNumber The record number that references the record that should
     *        be read.
     *
     * @throws IllegalStateException if the used channel is closed, if no file
     *         is currently selected, if the currently selected file is not a
     *         record based file or if the record couldn't be read.
     * @throws IllegalArgumentException if the file couldn't be selected via
     *         SFI.
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the defined sfi is not valid or if
     *         the defined record ID is invalid.
     * @throws SecurityException if the operation is not allowed because the
     *         security conditions are not satisfied.
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public Record readRecord(int sfi, int recNumber)
            throws IllegalStateException,
            IllegalArgumentException, SecurityException,
            UnsupportedOperationException, IOException {

        if ((sfi < SFI_MIN_VALUE || sfi > SFI_MAX_VALUE)
                && (sfi != CURRENT_FILE)) {
            throw new IllegalArgumentException(ErrorStrings.INVALID_SFI);
        }

        if (recNumber < REC_NUMBER_MIN_VALUE
                || recNumber > REC_NUMBER_MAX_VALUE) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidValue("recordNumber"));
        }

        // Prepare and send the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_READ_RECORD_B2);
        apdu.setP1((byte) recNumber);
        // SFI represents the most significant 5 bits
        apdu.setP2((byte) ((sfi << 3) | 4));
        apdu.setLE((byte) 0x00);
        byte[] apduResponse = apdu.sendApdu();

        // Handle the response
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            return new Record(
                    recNumber,
                    ResponseApdu.getResponseData(apduResponse));
        case ResponseApdu.SW_COMMAND_INCOMPATIBLE:
            throw new IllegalStateException(ErrorStrings.NO_RECORD_BASED_FILE);
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException(
                    ErrorStrings.OPERATION_NOT_SUPORTED);
        case ResponseApdu.SW_FILE_OR_APP_NOT_FOUND:
            if (sfi == CURRENT_FILE) {
                throw new IllegalStateException(
                        ErrorStrings.FILE_NOT_FOUND);
            } else {
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(
                    ErrorStrings.FILE_NOT_FOUND);
            }
        case ResponseApdu.SW_RECORD_NOT_FOUND:
            // If the record is not found, return null.
            return null;
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException(
                    ErrorStrings.OPERATION_NOT_SUPORTED);
        default:
            throw new IOException(ErrorStrings.unexpectedStatusWord(swValue));
        }
    }

    /**
     * Writes a record into the specified file.
     * <p>
     * <b>Note:</b> This method is based on the ISO/IEC 7816-4 command APPEND
     * RECORD and UPDATE RECORD (which replaces existing bytes).
     *
     * @param sfi The SFI of the file which shall be selected for this write
     *        operation. CURRENT_FILE can be applied if the file is already
     *        selected. The SFI must be in the range of (1-30).
     * @param rec The Record that shall be written.
     *
     * @throws IllegalStateException if the used channel is closed, if no file
     *         is currently selected, if the currently selected file is not a
     *         record based file or if the record couldn't be written.
     * @throws IllegalArgumentException if the file couldn't be selected via
     *         SFI.
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the defined Record is invalid, if the
     *         defined SFI is not valid.
     * @throws SecurityException if the operation is not allowed because the
     *         security conditions are not satisfied.
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public void writeRecord(int sfi, Record rec)
            throws IllegalArgumentException, IllegalStateException,
            SecurityException,
            UnsupportedOperationException, IOException {

        if (rec == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("rec"));
        }

        if ((sfi < SFI_MIN_VALUE || sfi > SFI_MAX_VALUE)
                && (sfi != CURRENT_FILE)) {
            throw new IllegalArgumentException(ErrorStrings.INVALID_SFI);
        }

        // Prepare and send the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        byte[] apduResponse = {};
        if (rec.getNumber() == APPEND_RECORD) {
            apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
            apdu.setIns(CommandApdu.INS_APPEND_RECORD);
            apdu.setP1((byte) 0x00);
            // SFI is most significant 5 bits
            apdu.setP2((byte) ((sfi << 3) | 0));
            apdu.setData(rec.getData());
        } else {
            // Try to update record. If record is not found, try appending it.
            // Prepare and send the APDU
            apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
            apdu.setIns(CommandApdu.INS_UPDATE_RECORD_DC);
            apdu.setP1((byte) rec.getNumber());
            // SFI is most significant 5 bits
            apdu.setP2((byte) ((sfi << 3) | 4));
            apdu.setData(rec.getData());
        }

        apduResponse = apdu.sendApdu();
        // Handle the response
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            return;
        case ResponseApdu.SW_WRONG_LENGTH:
            throw new IllegalArgumentException(ErrorStrings.WRONG_LENGTH);
        case ResponseApdu.SW_MEMORY_FAILURE:
            throw new IllegalStateException(ErrorStrings.MEMORY_FAILURE);
        case ResponseApdu.SW_COMMAND_INCOMPATIBLE:
            throw new IllegalStateException(ErrorStrings.NO_RECORD_BASED_FILE);
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_COMMAND_NOT_ALLOWED:
            throw new IllegalStateException(ErrorStrings.NO_CURRENT_FILE);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException(
                    ErrorStrings.OPERATION_NOT_SUPORTED);
        case ResponseApdu.SW_FILE_OR_APP_NOT_FOUND:
            if (sfi == CURRENT_FILE) {
                throw new IllegalStateException(
                        ErrorStrings.NO_CURRENT_FILE);
            } else {
                // TODO: should be an IllegalReferenceError
                throw new IllegalArgumentException(
                        ErrorStrings.FILE_NOT_FOUND);
            }
        case ResponseApdu.SW_RECORD_NOT_FOUND:
            throw new IllegalArgumentException(ErrorStrings.RECORD_NOT_FOUND);
        case ResponseApdu.SW_NOT_ENOUGH_MEMORY:
            throw new IllegalStateException(ErrorStrings.NOT_ENOUGH_MEMORY);
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException(
                    ErrorStrings.OPERATION_NOT_SUPORTED);
        default:
            // ISO/IEC 7816-4, Chapter 7.3.2:
            // In this group of commands, SW1-SW2 set to '63CX' indicates a
            // successful change of memory state, but after an internal retry
            // routine; 'X' > '0' encodes the number of retries; 'X' = '0'
            // means that no counter is provided.
            if (ResponseApdu.SW_CTR_MIN <= swValue
            && swValue <= ResponseApdu.SW_CTR_MAX) {
                return;
            } else {
                throw new IOException(
                        ErrorStrings.unexpectedStatusWord(swValue));
            }
        }
    }

    /**
     * Returns the record numbers that contains the defined search pattern.
     * <p>
     * <b>Note:</b>This method is based on the ISO/IEC 7816-4 command SEARCH
     * RECORD with simple search.
     *
     * @return A list of record numbers (position 1..n of the record in the
     *         file) of the records which match to the search pattern. If no
     *         record matches then null will be returned.
     *
     * @param sfi The SFI of the file which shall be selected for this search
     *        operation. CURRENT_FILE can be applied if the file is already
     *        selected. The sfi must be in the range of (1-30).
     * @param searchPattern The pattern that shall match with Records.
     *
     * @throws IllegalStateException if the used channel is closed, if no file
     *         is currently selected, if the currently selected file is not a
     *         record based file or if the data couldn't be searched.
     * @throws IllegalArgumentException if the file couldn't be selected via
     *         SFI.
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the defined SFI is not valid, if the
     *         search pattern is empty or if the search pattern is too long.
     * @throws SecurityException if the operation is not allowed because the
     *         security conditions are not satisfied.
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public int[] searchRecord(int sfi, byte[] searchPattern)
            throws IllegalStateException,
            IllegalArgumentException, SecurityException,
            UnsupportedOperationException, IOException {

        if ((sfi < SFI_MIN_VALUE || sfi > SFI_MAX_VALUE)
                && (sfi != CURRENT_FILE)) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidValue("sfi"));
        }

        if (searchPattern == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("searchPattern"));
        }

        if (searchPattern.length == 0
                || searchPattern.length > CommandApdu.MAX_DATA_LENGTH) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("searchPattern"));
        }

        // Form the APDU.
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_SEARCH_RECORD);
        // Start search from Rec #1
        apdu.setP1((byte) 0x01);
        // SFI is most significant 5 bits
        // 0x04: Forward search from record in P1
        apdu.setP2((byte) ((sfi << 3) | 4));
        apdu.setData(searchPattern);
        apdu.setLE((byte) 0x00);
        byte[] apduResponse = apdu.sendApdu();

        // Handle the response
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            byte[] responseData = ResponseApdu.getResponseData(apduResponse);
            if (responseData.length > 0) {
                int[] recordNumbers = new int[responseData.length];

                for (int i = 0; i < responseData.length; i++) {
                    // AND with 0xFF to erase sign information.
                    recordNumbers[i] = (byte) (responseData[i] & (byte) 0xFF);
                }

                return recordNumbers;
            } else {
                return null;
            }
        case ResponseApdu.SW_COMMAND_INCOMPATIBLE:
            throw new IllegalStateException(ErrorStrings.NO_RECORD_BASED_FILE);
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_COMMAND_NOT_ALLOWED:
            throw new IllegalStateException(ErrorStrings.NO_CURRENT_FILE);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
                throw new UnsupportedOperationException(
                        ErrorStrings.OPERATION_NOT_SUPORTED);
        case ResponseApdu.SW_FILE_OR_APP_NOT_FOUND:
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(ErrorStrings.FILE_NOT_FOUND);
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException(
                    ErrorStrings.OPERATION_NOT_SUPORTED);
        default:
            throw new IOException(ErrorStrings.unexpectedStatusWord(swValue));
        }
    }

    /**
     * Reads content of the selected transparent file at the position specified
     * by offset and length.
     * <p>
     * <b>Note:</b>This method is based on the ISO/IEC 7816-4 command READ
     * BINARY.
     *
     * @return The data read from the file or null if no content is available.
     *
     * @param sfi The SFI of the file which shall be selected for this read
     *        operation. CURRENT_FILE can be applied if the file is already
     *        selected. The sfi must be in the range of (1-30).
     * @param offset Defines the start point of the file where the data should
     *        be read.
     * @param length Defines the length of the data which should be read. If set
     *        to 0, all possible data within the limit of
     *        {@link CommandApdu#MAX_DATA_LENGTH} will be read.
     *
     * @throws IllegalStateException if the used channel is closed, if no file
     *         is currently selected, if the currently selected file is not a
     *         transparent file or if the data couldn't be read.
     * @throws IllegalArgumentException if the file couldn't be selected via
     *         SFI.
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the defined sfi is not valid or if
     *         the defined offset and length couldn't be applied.
     * @throws SecurityException if the operation is not allowed because the
     *         security conditions are not satisfied.
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public byte[] readBinary(int sfi, int offset, int length)
            throws IllegalStateException,
            IllegalArgumentException, SecurityException,
            UnsupportedOperationException, IOException {

        if ((sfi < SFI_MIN_VALUE || sfi > SFI_MAX_VALUE)
                && (sfi != FileViewProvider.CURRENT_FILE)) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidValue("sfi"));
        }

        if (offset < 0) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidValue("offset"));
        }

        if (length < 0) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidValue("length"));
        }

        // Form the APDU
        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_READ_BINARY_B0);
        if (sfi == CURRENT_FILE) {
            if (offset > OFFSET_LONG_MAX_VALUE) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidValue("offset"));
            }
            if (length > OFFSET_LONG_MAX_VALUE) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidValue("length"));
            }

            // b8 = 0. b7 to b1 encode the 7 MSBs of offset.
            apdu.setP1((byte) (0x7F & (offset >> 8)));
            apdu.setP2((byte) offset);
        } else {
            if (offset > OFFSET_SHORT_MAX_VALUE) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidValue("offset"));
            }
            if (length > OFFSET_SHORT_MAX_VALUE) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidValue("length"));
            }

            // Set b8 = 1, b7 = b6 = 0 and b5 to b1 encode sfi.
            apdu.setP1((byte) (0x80 | sfi));
            apdu.setP2((byte) offset);
        }
        apdu.setLE(length);
        // Send the APDU
        byte[] apduResponse = apdu.sendApdu();

        // Handle the response
        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            return ResponseApdu.getResponseData(apduResponse);
        case ResponseApdu.SW_COMMAND_INCOMPATIBLE:
            // Not a binary file
            throw new IllegalStateException(
                    ErrorStrings.NO_TRANSPARENT_FILE);
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_COMMAND_NOT_ALLOWED:
            // No file selected
            throw new IllegalStateException(
                    ErrorStrings.NO_CURRENT_FILE);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        case ResponseApdu.SW_FILE_OR_APP_NOT_FOUND:
            if (sfi == CURRENT_FILE) {
                throw new IllegalStateException(
                        ErrorStrings.FILE_NOT_FOUND);
            } else {
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(
                    ErrorStrings.FILE_NOT_FOUND);
            }
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        default:
            throw new IOException(ErrorStrings.unexpectedStatusWord(swValue));
        }
    }

    /**
     * Writes the defined data into the selected file at the position specified
     * by offset and length.
     * <p>
     * <b>Note:</b>This method is based on the ISO/IEC 7816-4 command UPDATE
     * BINARY.
     *
     * @param sfi The SFI of the file which shall be selected for this write
     *        operation. CURRENT_FILE can be applied if the file is already
     *        selected. The sfi must be in the range of (1-30).
     * @param data The data which shall be written.
     *
     * @param offset Defines the position in the file where the data should be
     *        stored.
     * @param length Defines the length of the data which shall be written.
     *
     * @throws IllegalStateException if the used channel is closed, if no file
     *         is currently selected, if the currently selected file is not a
     *         transparent file or if the record couldn't be written.
     * @throws IllegalArgumentException if the file couldn't be selected via
     *         SFI.
     *         TODO: should be an IllegalReferenceError
     * @throws IllegalArgumentException if the defined sfi is not valid, if the
     *         defined data array is empty or too short or if the defined offset
     *         and length couldn't be applied.
     * @throws SecurityException if the operation is not allowed because the
     *         security conditions are not satisfied.
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws IOException Lower-lever API exception.
     */
    public void writeBinary(int sfi, byte[] data, int offset, int length)
            throws IllegalStateException,
            IllegalArgumentException, SecurityException,
            UnsupportedOperationException, IOException {

        if (data == null) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramNull("data"));
        }

        if (data.length == 0
                || data.length > CommandApdu.MAX_DATA_LENGTH
                || data.length != length) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidArrayLength("data"));
        }

        if ((sfi < SFI_MIN_VALUE || sfi > SFI_MAX_VALUE)
                && (sfi != FileViewProvider.CURRENT_FILE)) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidValue("sfi"));
        }

        if (offset < 0) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidValue("offset"));
        }

        if (length < 0) {
            throw new IllegalArgumentException(
                    ErrorStrings.paramInvalidValue("length"));
        }

        CommandApdu apdu = new CommandApdu(getChannel());
        apdu.setCla(CommandApdu.CLA_INTERINDUSTRY);
        apdu.setIns(CommandApdu.INS_UPDATE_BINARY_D6);
        if (sfi == CURRENT_FILE) {
            if (offset > OFFSET_LONG_MAX_VALUE) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidValue("offset"));
            }

            // b8 = 0. b7 to b1 encode the 7 MSBs of offset.
            apdu.setP1((byte) (0x7F & (offset >> 8)));
            apdu.setP2((byte) offset);
        } else {
            if (offset > OFFSET_SHORT_MAX_VALUE) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidValue("offset"));
            }

            // Set b8 = 1, b7 = b6 = 0 and b5 to b1 encode sfi.
            apdu.setP1((byte) (0x80 | (0x9F & sfi)));
            apdu.setP2((byte) offset);
        }
        apdu.setData(data);
        byte[] apduResponse = apdu.sendApdu();

        int swValue = ResponseApdu.getResponseStatusWordValue(apduResponse);
        switch (swValue) {
        case ResponseApdu.SW_NO_FURTHER_QUALIFICATION:
            return;
        case ResponseApdu.SW_COMMAND_INCOMPATIBLE:
            // Not a binary file
            throw new IllegalStateException(
                    ErrorStrings.NO_TRANSPARENT_FILE);
        case ResponseApdu.SW_SECURITY_STATUS_NOT_SATISFIED:
            throw new SecurityException(
                    ErrorStrings.SECURITY_STATUS_NOT_SATISFIED);
        case ResponseApdu.SW_COMMAND_NOT_ALLOWED:
            // No file selected
            throw new IllegalStateException(
                    ErrorStrings.NO_CURRENT_FILE);
        case ResponseApdu.SW_FUNC_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        case ResponseApdu.SW_FILE_OR_APP_NOT_FOUND:
            if (sfi == CURRENT_FILE) {
                throw new IllegalStateException(
                        ErrorStrings.FILE_NOT_FOUND);
            } else {
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(
                    ErrorStrings.FILE_NOT_FOUND);
            }
        case ResponseApdu.SW_WRONG_PARAMETERS_P1P2:
            throw new IllegalArgumentException(
                    ErrorStrings.OFFSET_OUTSIDE_EF);
        case ResponseApdu.SW_INS_NOT_SUPPORTED:
            throw new UnsupportedOperationException();
        default:
            throw new IOException(ErrorStrings.unexpectedStatusWord(swValue));
        }
    }
}
