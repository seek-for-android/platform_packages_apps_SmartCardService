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
import java.util.Arrays;

import org.simalliance.openmobileapi.FileViewProvider.FCP;
import org.simalliance.openmobileapi.internal.ByteArrayConverter;
import org.simalliance.openmobileapi.internal.DerTlvCoder;
import org.simalliance.openmobileapi.internal.DerTlvParser;
import org.simalliance.openmobileapi.internal.ErrorStrings;
import org.simalliance.openmobileapi.internal.OidParser;
import org.simalliance.openmobileapi.internal.TlvEntryWrapper;


/**
 * This Provider class offers basic services to access a PKCS#15 file system.
 * This Provider requires a PKCS#15 data structure on the Secure Element and a
 * Channel instance allowing the access to this PKCS#15 data structure.
 */
public class PKCS15Provider extends Provider {

    /**
     * The FileViewProvider object that will allow interaction with
     * the underlying file system.
     */
    private FileViewProvider mFileViewProvider;

    /**
     * The content of EF(ODF).
     */
    private byte[] mOdfContent;
    /**
     * The content of EF(TokenInfo).
     */
    private byte[] mTokenInfoContent;

    /**
     * Default PKCS#15 AID.
     */
    public static final byte[] AID_PKCS15 = {(byte) 0xA0, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x63, (byte) 0x50, (byte) 0x4B,
            (byte) 0x43, (byte) 0x53, (byte) 0x2D, (byte) 0x31, (byte) 0x35};

    // Relevant file identifiers
    /**
     * The FID of the EF(DIR).
     */
    private static final int FID_EF_DIR = 0x2F00;
    /**
     * The FID of the EF(ODF).
     */
    private static final int FID_EF_ODF = 0x5031;
    /**
     * The FID of the EF(TokenInfo).
     */
    private static final int FID_EF_TOKEN_INFO = 0x5032;

    // Relevant TLV tags
    /**
     * PKCS#15 application template TLV tag.
     */
    private static final byte[] TLV_TAG_PKCS15_APP_TEMPLATE     = {(byte) 0x61};
    /**
     * PKCS#15 DF path TLV tag.
     */
    private static final byte[] TLV_TAG_PKCS15_PATH             = {(byte) 0x51};
    /**
     * PKCS#15 OID TLV tag.
     */
    private static final byte[] TLV_TAG_OID                     = {(byte) 0x06};
    /**
     * PKCS#15 Sequence TLV tag.
     */
    private static final byte[] TLV_TAG_SEQUENCE                = {(byte) 0x30};
    /**
     * PKCS#15 Private Key TLV tag.
     */
    private static final byte[] TLV_TAG_PRIVATE_KEY             = {(byte) 0xA0};
    /**
     * PKCS#15 Public Key TLV tag.
     */
    private static final byte[] TLV_TAG_PUBLIC_KEY              = {(byte) 0xA1};
    /**
     * PKCS#15 trusted Public Key TLV tag.
     */
    private static final byte[] TLV_TAG_PUBLIC_KEY_TRUSTED      = {(byte) 0xA2};
    /**
     * PKCS#15 Secret Key TLV tag.
     */
    private static final byte[] TLV_TAG_SECRET_KEY              = {(byte) 0xA3};
    /**
     * PKCS#15 Certificate TLV tag.
     */
    private static final byte[] TLV_TAG_CERTIFICATE             = {(byte) 0xA4};
    /**
     * PKCS#15 trusted Certificate TLV tag.
     */
    private static final byte[] TLV_TAG_CERTIFICATE_TRUSTED     = {(byte) 0xA5};
    /**
     * PKCS#15 useful Certificate TLV tag.
     */
    private static final byte[] TLV_TAG_CERTIFICATE_USEFUL      = {(byte) 0xA6};
    /**
     * PKCS#15 Data Object TLV tag.
     */
    private static final byte[] TLV_TAG_DATA_OBJECT             = {(byte) 0xA7};
    /**
     * PKCS#15 Authenticate Object TLV tag.
     */
    private static final byte[] TLV_TAG_AUTHENTICATE_OBJECT     = {(byte) 0xA8};

    /**
     * Encapsulates the defined channel by a PKCS#15 file system object. This
     * method checks the presence of the EF(ODF) (Object Directory File) with
     * file identifier 5031 and of the EF(TokenInfo) with file identifier 5032.
     * Both files are mandatory and must be present in a valid PKCS#15 file
     * system. This method must first try to select EF(ODF) and EF(TokenInfo) on
     * the provided channel. If the select fails, this method must try to locate
     * a DF(PKCS#15) in the legacy file system using the EF(DIR) according to
     * the data structure described in chapter 5.4 of the PKCS#15 specification
     * (v1.1).
     *
     * @param channel The channel that shall be used by this Provider for file
     *        operations.
     *
     * @throws IOException if no PKCS#15 file system is detected on the provided
     *         channel.
     * @throws IllegalStateException if the defined channel is closed.
     */
    public PKCS15Provider(Channel channel) throws IOException,
            IllegalStateException {

        // Call super constructor and initialize the FVP
        super(channel);
        mFileViewProvider = new FileViewProvider(channel);

        // Check if the PKCS#15 file structure is present in the current DF
        if (currentDirIsPkcs15FileStructure()) {
            mOdfContent = readOdf();
            mTokenInfoContent = readTokenInfo();
        } else {
            // If not present, read EF(DIR)
            FCP fcpEfDir;
            try {
                // Try selecting EF(DIR)
                fcpEfDir = mFileViewProvider.selectByPath(
                        Integer.toHexString(FID_EF_DIR), false);
            } catch (IllegalArgumentException e) {
                // TODO: should be an IllegalReferenceError
                throw new IOException(ErrorStrings.PKCS15_NO_FS);
            }

            // Look for path element in EF(DIR)
            int numberOfRecords = fcpEfDir.getNumberOfRecords();
            for (int i = 0; i < numberOfRecords; i++) {
                // Read the record and get the data
                byte[] recordData = mFileViewProvider.readRecord(
                        FileViewProvider.CURRENT_FILE, i + 1).getData();

                // Check if this record contains a path to a valid
                // PKCS#15 File Structure
                // TODO: support referencing by ADF (not implemented)
                if (recordContainsValidPath(recordData)) {
                    mOdfContent = readOdf();
                    mTokenInfoContent = readTokenInfo();
                    return;
                }
            }

            // If all records has been read and no valid path has been found...
            throw new IOException(ErrorStrings.PKCS15_NO_FS);
        }
    }

    /**
     * Returns the raw content of the EF(ODF) (Object Directory File).
     *
     * @return The EF(ODF) as a byte array. Must not be null.
     *
     * @throws IllegalStateException if the defined channel is closed.
     */
    public byte[] getODF() throws IllegalStateException {
        return mOdfContent;
    }

    /**
     * Returns the raw content of the EF(TokenInfo).
     *
     * @return The EF(TokenInfo) as a byte array. Must not be null.
     */
    public byte[] getTokenInfo() {
        return mTokenInfoContent;
    }

    /**
     * Returns an array of EF(PrKDF) paths (Private Key Directory Files). The
     * PKCS#15 file system may contain zero, one or several EF(PrKDF).
     *
     * @return The array of EF(PrKDF) paths. May be null if empty.
     */
    public Path[] getPrivateKeyPaths() {
        ArrayList<Path> paths = new ArrayList<Path>();
        int position = 0;
        DerTlvParser parser = new DerTlvParser();
        byte[] odfContent = parser.getValidTlvData(getODF());

        while (position < odfContent.length) {
            // Parse the next DER entry
            TlvEntryWrapper derObject
                    = new TlvEntryWrapper(odfContent, position, parser);
            if (isPrivateKeyTag(derObject.getTag())) {
                try {
                    paths.add(decodePath(derObject.getValue()));
                } catch (IllegalArgumentException e) {
                    // If path could not be parsed, ignore it
                }
            }

            // Increase the position
            position += derObject.getTotalLength();
        }

        if (paths.size() > 0) {
            return paths.toArray(new Path[paths.size()]);
        } else {
            return null;
        }
    }

    /**
     * Returns an array of EF(PuKDF) paths (Public Key Directory Files). The
     * PKCS#15 file system may contain zero, one or several EF(PuKDF).
     *
     * @return The array of EF(PuKDF) paths. May be null if empty.
     */
    public Path[] getPublicKeyPaths() {
        ArrayList<Path> paths = new ArrayList<Path>();
        int position = 0;
        DerTlvParser parser = new DerTlvParser();
        byte[] odfContent = parser.getValidTlvData(getODF());

        while (position < odfContent.length) {
            // Parse the next DER entry
            TlvEntryWrapper derObject
                    = new TlvEntryWrapper(odfContent, position, parser);
            if (isPublicKeyTag(derObject.getTag())) {
                try {
                    paths.add(decodePath(derObject.getValue()));
                } catch (IllegalArgumentException e) {
                    // If path could not be parsed, ignore it
                }
            }

            // Increase the position
            position += derObject.getTotalLength();
        }

        if (paths.size() > 0) {
            return paths.toArray(new Path[paths.size()]);
        } else {
            return null;
        }
    }

    /**
     * Returns an array of EF(CDF) paths (Certificate Directory Files). The
     * PKCS#15 file system may contain zero, one or several EF(CDF).
     *
     * @return The array of EF(CDF) paths. May be null if empty.
     */
    public Path[] getCertificatePaths() {
        ArrayList<Path> paths = new ArrayList<Path>();
        int position = 0;
        DerTlvParser parser = new DerTlvParser();
        byte[] odfContent = parser.getValidTlvData(getODF());

        while (position < odfContent.length) {
            // Parse the next DER entry
            TlvEntryWrapper derObject
                    = new TlvEntryWrapper(odfContent, position, parser);
            if (isCertificateTag(derObject.getTag())) {
                try {
                    paths.add(decodePath(derObject.getValue()));
                } catch (IllegalArgumentException e) {
                    // If path could not be parsed, ignore it
                }
            }

            // Increase the position
            position += derObject.getTotalLength();
        }

        if (paths.size() > 0) {
            return paths.toArray(new Path[paths.size()]);
        } else {
            return null;
        }
    }

    /**
     * Returns an array of EF(DODF) paths (Data Object Directory Files). The
     * PKCS#15 file system may contain zero, one or several EF(DODF).
     *
     * @return The array of EF(DODF) paths. May be null if empty.
     */
    public Path[] getDataObjPaths() {
        ArrayList<Path> paths = new ArrayList<Path>();
        int position = 0;
        DerTlvParser parser = new DerTlvParser();
        byte[] odfContent = parser.getValidTlvData(getODF());

        while (position < odfContent.length) {
            // Parse the next DER entry
            TlvEntryWrapper derObject
                    = new TlvEntryWrapper(odfContent, position, parser);
            if (isDataObjectTag(derObject.getTag())) {
                try {
                    paths.add(decodePath(derObject.getValue()));
                } catch (IllegalArgumentException e) {
                    // If path could not be parsed, ignore it
                }
            }

            // Increase the position
            position += derObject.getTotalLength();
        }

        if (paths.size() > 0) {
            return paths.toArray(new Path[paths.size()]);
        } else {
            return null;
        }
    }

    /**
     * Returns an array of EF(AODF) paths (Authentication Object Directory
     * Files). The PKCS#15 file system may contain zero, one or several
     * EF(AODF).
     *
     * @return The array of EF(AODF) paths. May be null if empty.
     */
    public Path[] getAuthObjPaths() {
        ArrayList<Path> paths = new ArrayList<Path>();
        int position = 0;
        DerTlvParser parser = new DerTlvParser();
        byte[] odfContent = parser.getValidTlvData(getODF());

        while (position < odfContent.length) {
            // Parse the next DER entry
            TlvEntryWrapper derObject
                    = new TlvEntryWrapper(odfContent, position, parser);
            if (isAuthenticationObjectTag(derObject.getTag())) {
                try {
                    paths.add(decodePath(derObject.getValue()));
                } catch (IllegalArgumentException e) {
                    // If path could not be parsed, ignore it
                }
            }

            // Increase the position
            position += derObject.getTotalLength();
        }

        if (paths.size() > 0) {
            return paths.toArray(new Path[paths.size()]);
        } else {
            return null;
        }
    }

    /**
     * Selects and reads a PKCS#15 file. The file may be a transparent or linear
     * fixed EF. The 'index' and 'length' fields of the Path instance will be
     * used according to chapter 6.1.5 of the PKCS#15 specification (v1.1). In
     * case of transparent EF, 'index' is the start offset in the file and
     * 'length' is the length to read. In case of linear fixed EF, 'index' is
     * the record to read.
     *
     * @param path Path of the file.
     *
     * @return The file content as a byte array. Or null if the referenced path
     *         does not exist.
     *
     * @throws UnsupportedOperationException if this operation is not supported.
     * @throws SecurityException if the operation cannot be performed if a
     *         security condition is not satisfied.
     * @throws IllegalArgumentException if the PKCS#15 file cannot be selected
     *         or read. TODO: should be an IllegalReferenceError
     * @throws IOException Lower-lever API exception.
     * @throws IllegalStateException if the used channel is closed.
     */
    public byte[] readFile(Path path) throws SecurityException,
            UnsupportedOperationException, IOException,
            IllegalArgumentException, IllegalStateException {

        FCP fcp = mFileViewProvider.selectByPath(
                ByteArrayConverter.byteArrayToPathString(path.getPath()), true);

        // Check that it is an EF
        if (fcp.getFileType() != FCP.FILETYPE_EF) {
            // TODO: should be an IllegalReferenceError
            throw new IllegalArgumentException(
                    "Could not read file: not an EF.");
        }

        // Determine whether it is binary or record-based file.
        if (fcp.getFileStructure() == FCP.FILESTRUCTURE_TRANSPARENT) {
            int index, length;
            if (path.hasIndexLength()) {
                index = path.getIndex();
                length = path.getLength();
            } else {
                index = 0;
                length = 0;
            }

            return mFileViewProvider.readBinary(
                    FileViewProvider.CURRENT_FILE, index, length);
        } else {
            // We need the index to know which record to read.
            if (!path.hasIndexLength()) {
                // TODO: should be an IllegalReferenceError
                throw new IllegalArgumentException(
                        "Could not read file: index not specified"
                                + " in a record-based file.");
            }

            return mFileViewProvider.readRecord(FileViewProvider.CURRENT_FILE,
                    path.getIndex()).getData();
        }
    }

    /**
     * Parses the raw content of an EF(DODF) and searches for a specific OID
     * Data Object. This method is a convenience method to simplify the access
     * to OID Data Objects by applications, as described in chapter 6.7.4 of the
     * PKCS#15 specification (v1.1). In many cases, the EF(DODF) contains a
     * simple OID Data Object with a Path object, in order to reference an
     * application-specific EF. For example, the OMA-DM specification requires a
     * EF(DODF) containing the OID 2.23.43.7.1, followed by a Path object,
     * referencing the EF(DM_Bootstrap).
     *
     * @param dodf The raw content of an EF(DODF) to parse.
     * @param oid The searched OID value (e.g. OMA-DM bootstrap OID is
     *        2.23.43.7.1).
     *
     * @return The raw object value if OID has been found, null if not found.
     *
     * @throws IllegalArgumentException if the OID is not correct.
     * @throws UnsupportedOperationException if this operation is not supported.
     */
    public byte[] searchOID(byte[] dodf, String oid)
            throws IllegalArgumentException, UnsupportedOperationException {
        byte[] encodedOid = OidParser.encodeOid(oid);
        DerTlvParser parser = new DerTlvParser();
        TlvEntryWrapper entry;
        try {
            entry = new TlvEntryWrapper(dodf, 0, parser);
        } catch (Exception e) {
            return null;
        }

        // Ensure that the first tag is a DataObject
        if (!Arrays.equals(entry.getTag(), TLV_TAG_DATA_OBJECT)) {
            return null;
        }

        // Get the actual content and start parsing it
        byte[] outerContent = entry.getValue();
        int outerPosition = 0;
        while (outerPosition < outerContent.length) {
            TlvEntryWrapper outerTlvEntry;
            try {
                outerTlvEntry = new TlvEntryWrapper(
                        outerContent, outerPosition, parser);
            } catch (Exception e) {
                return null;
            }

            // Check if it is a sequence object
            if (Arrays.equals(outerTlvEntry.getTag(), TLV_TAG_SEQUENCE)) {
                int innerPosition = 0;
                byte[] innerContent = outerTlvEntry.getValue();
                TlvEntryWrapper innerTlvEntry;
                try {
                    innerTlvEntry = new TlvEntryWrapper(
                            innerContent, innerPosition, parser);
                } catch (Exception e) {
                    outerPosition += outerTlvEntry.getTotalLength();
                    continue;
                }

                // Check if first inner entry is an OID
                if (Arrays.equals(innerTlvEntry.getTag(), TLV_TAG_OID)) {
                    // Check if the OID is the desired one
                    if (Arrays.equals(encodedOid, innerTlvEntry.getValue())) {
                        // If it is, return the value besides this OID
                        innerPosition += innerTlvEntry.getTotalLength();
                        try {
                            innerTlvEntry = new TlvEntryWrapper(
                                    innerContent, innerPosition, parser);
                        } catch (Exception e) {
                            outerPosition += outerTlvEntry.getTotalLength();
                            continue;
                        }

                        return innerTlvEntry.getValue();
                    }
                }
            }

            // If it was not what it was expected, move to the next outer entry.
            outerPosition += outerTlvEntry.getTotalLength();
        }

        // If OID was not found, return null
        return null;
    }

    /**
     * Builds a Path object using a DER-encoded (see ITU X.690 for DER-Coding)
     * buffer.
     *
     * @param der the DER-encoded Path object as a byte array.
     *
     * @return The Path object.
     *
     * @throws IllegalArgumentException if the defined path is not a correctly
     *         DER-encoded buffer.
     */
    public Path decodePath(byte[] der) throws IllegalArgumentException {

        // Start reading the sequence object
        DerTlvParser parser = new DerTlvParser();
        TlvEntryWrapper derPathObject = new TlvEntryWrapper(der, 0, parser);
        if (!Arrays.equals(derPathObject.getTag(), DerTlvCoder.TAG_SEQUENCE)) {
            throw new IllegalArgumentException(ErrorStrings.TLV_TAG_UNEXPECTED);
        }
        byte[] sequenceBytes = derPathObject.getValue();

        int position = 0;

        // Parse the next DER entry, which should be the path value.
        TlvEntryWrapper derPathValue = new TlvEntryWrapper(
                sequenceBytes, position, parser);
        if (!Arrays.equals(
                derPathValue.getTag(),
                DerTlvCoder.TAG_OCTET_STRING)) {
            throw new IllegalArgumentException(ErrorStrings.TLV_TAG_UNEXPECTED);
        }
        position += derPathValue.getTotalLength();

        // Check if index and length are present
        if (position >= sequenceBytes.length) {
            // They are not
            return new Path(derPathValue.getValue());
        } else {
            // Parse index
            TlvEntryWrapper derIndex = new TlvEntryWrapper(sequenceBytes,
                    position, parser);
            if (!Arrays.equals(derIndex.getTag(), DerTlvCoder.TAG_INTEGER)) {
                throw new IllegalArgumentException(
                        ErrorStrings.TLV_TAG_UNEXPECTED);
            }
            int index = ByteArrayConverter.byteArrayToInt(derIndex.getValue());
            position += derIndex.getTotalLength();

            // Parse length
            TlvEntryWrapper derLength = new TlvEntryWrapper(sequenceBytes,
                    position, parser);
            if (!Arrays.equals(derLength.getTag(), DerTlvCoder.TAG_INTEGER)) {
                throw new IllegalArgumentException(
                        ErrorStrings.TLV_TAG_UNEXPECTED);
            }
            int length = ByteArrayConverter.byteArrayToInt(derLength.getValue());

            return new Path(derPathValue.getValue(), index, length);
        }
    }

    /**
     * This class represents a Path object as defined in chapter 6.1.5 of the
     * PKCS#15 specification (v1.1).
     */
    public class Path {

        /**
         * Undefined value.
         */
        public static final int VALUE_UNDEFINED = -1;

        /**
         * The path itself.
         */
        private byte[] mPath;

        /**
         * For linear record files, mIndex shall be the record number (in the
         * ISO/IEC 7816-4 definition).
         *
         * For transparent files, mIndex can be used to specify an offset within
         * the file.
         */
        private Integer mIndex;

        /**
         * For linear record file, mLength can be set to 0 (if the card's
         * operating system allows an Le parameter equal to 0 in a READ RECORD
         * command). Lengths of fixed records may be found in the TokenInfo file
         * as well (see Section 6.9).
         *
         * For transparent file, mLength is the length of the segment to read.
         */
        private Integer mLength;

        /**
         * Builds a Path object without index and length (the path can be
         * absolute as well as relative).
         *
         * @param path the path as a byte array.
         *
         * @throws IllegalArgumentException if the path is not correct.
         */
        public Path(byte[] path) throws IllegalArgumentException {
            if (path == null) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramNull("path"));
            }

            mPath = new byte[path.length];
            System.arraycopy(path, 0, mPath, 0, path.length);
            mIndex = null;
            mLength = null;
        }

        /**
         * Builds a Path object with index and length (the path can be absolute
         * as well as relative).
         *
         * @param path The path as a byte array.
         * @param index The index value.
         * @param length The length value.
         *
         * @throws IllegalArgumentException if the path is not correct.
         */
        public Path(byte[] path, int index, int length)
                throws IllegalArgumentException {
            if (path == null) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramNull("path"));
            }

            if (index < 1) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidValue("index"));
            }
            if (length < 1) {
                throw new IllegalArgumentException(
                        ErrorStrings.paramInvalidValue("length"));
            }

            mPath = new byte[path.length];
            System.arraycopy(path, 0, mPath, 0, path.length);
            mIndex = Integer.valueOf(index);
            mLength = Integer.valueOf(length);
        }

        /**
         * Returns the path field of this Path object.
         *
         * @return The path field.
         */
        public byte[] getPath() {
            return mPath;
        }

        /**
         * Checks whether this Path object has an index and length fields.
         *
         * @return True if the index and length field is present, false
         *         otherwise.
         */
        public boolean hasIndexLength() {
            return mIndex != null && mLength != null;
        }

        /**
         * Returns the index field of this Path object. The value of this field
         * is undefined if the method hasIndexLength() returns false.
         *
         * @return The index field.
         */
        public int getIndex() {
            if (hasIndexLength()) {
                return mIndex.intValue();
            } else {
                return VALUE_UNDEFINED;
            }
        }

        /**
         * Returns the length field of this Path object. The value of this field
         * is undefined if the method hasIndexLength() returns false.
         *
         * @return The length field.
         */
        public int getLength() {
            if (hasIndexLength()) {
                return mLength.intValue();
            } else {
                return VALUE_UNDEFINED;
            }
        }

        /**
         * Encodes this Path object according to DER (see ITU X.690 for
         * DER-Coding).
         *
         * @return This Path object as a DER-encoded byte array.
         */
        public byte[] encode() {
            byte[] derCodedPath = DerTlvCoder.encodeOctetString(mPath);

            byte[] derCodedIndex;
            byte[] derCodedLength;
            if (hasIndexLength()) {
                derCodedIndex = DerTlvCoder.encodeInteger(mIndex);
                derCodedLength = DerTlvCoder.encodeInteger(mLength);
            } else {
                derCodedIndex = new byte[0];
                derCodedLength = new byte[0];
            }

            byte[] encodedDer = new byte[derCodedPath.length
                                         + derCodedIndex.length
                                         + derCodedLength.length];
            System.arraycopy(derCodedPath, 0, encodedDer, 0,
                    derCodedPath.length);
            System.arraycopy(derCodedIndex, 0, encodedDer, derCodedPath.length,
                    derCodedIndex.length);
            System.arraycopy(derCodedLength, 0, encodedDer, derCodedPath.length
                    + derCodedIndex.length, derCodedLength.length);

            return DerTlvCoder.encodeSequence(encodedDer);
        }
    }

    /* **************************************** */
    /* Private methods                          */
    /* **************************************** */

    /**
     * Checks whether the currently selected directory contains a valid PKCS#15
     * file structure.
     *
     * @return true if the currently selected directory contains a valid PKCS#15
     * file structure, false otherwise.
     *
     * @throws IllegalStateException if the used channel is closed.
     */
    private boolean currentDirIsPkcs15FileStructure()
            throws IllegalStateException {
        try {
            // Check that EF(ODF) and EF(TokenInfo) are present
            mFileViewProvider.selectByFID(FID_EF_ODF);
            mFileViewProvider.selectByFID(FID_EF_TOKEN_INFO);
            return true;
        } catch (IllegalStateException e) {
            // Channel is closed
            throw e;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Checks if a record entry in EF(DIR) contains a reference to a valid
     * PKCS#15 file structure.
     *
     * @param recordData The already-parsed TLV structure of the record.
     *
     * @return true if there is a valid reference to a PKCS#15 files structure,
     * false otherwise.
     */
    private boolean recordContainsValidPath(
            byte[] recordData) {
        int startPosition;
        DerTlvParser parser = new DerTlvParser();

        // Search for the PKCS#15 application template tag.
        try {
            startPosition = parser.searchTag(
                    recordData, TLV_TAG_PKCS15_APP_TEMPLATE, 0);
        } catch (IllegalArgumentException e) {
            // If tag is not found...
            return false;
        }

        // Get the content of the PKCS#15 application template
        byte[] pkcs15RawData = new TlvEntryWrapper(
                recordData, startPosition, parser).getValue();

        // Search for the "path" tag
        try {
            startPosition = parser.searchTag(
                    pkcs15RawData, TLV_TAG_PKCS15_PATH, startPosition);
        } catch (IllegalArgumentException e) {
            // If tag is not found...
            return false;
        }

        // Get the content of the Path
        byte [] rawPath = new TlvEntryWrapper(
                pkcs15RawData, startPosition, parser).getValue();
        try {
            // Select the specified folder and check that
            // contains a valid PKCS#15 FS
            mFileViewProvider.selectByPath(
                    ByteArrayConverter.byteArrayToPathString(rawPath), false);
            return currentDirIsPkcs15FileStructure();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Reads the content of EF(ODF).
     *
     * @return The content of EF(ODF) as a byte array. Must not be null.
     *
     * @throws IOException if a lower-level exception occurs.
     * @throws IOException if read operation returns null.
     */
    private byte[] readOdf() throws IOException {
        mFileViewProvider.selectByFID(FID_EF_ODF);
        byte[] odfContent = mFileViewProvider.readBinary(
                FileViewProvider.CURRENT_FILE, 0, 0);

        if (odfContent == null) {
            throw new IOException(
                    "Error reading EF(ODF): returned null.");
        }

        return odfContent;
    }

    /**
     * Reads the content of EF(TokenInfo).
     *
     * @return The content of EF(TokenInfo) as a byte array. Must not be null.
     *
     * @throws IOException if a lower-level exception occurs.
     * @throws IOException if read operation returns null.
     */
    private byte[] readTokenInfo() throws IOException {
        mFileViewProvider.selectByFID(FID_EF_TOKEN_INFO);
        byte[] tokenInfoContent = mFileViewProvider.readBinary(
                FileViewProvider.CURRENT_FILE, 0, 0);

        if (tokenInfoContent == null) {
            throw new IOException(
                    "Error reading EF(TokenInfo): returned null.");
        }

        return tokenInfoContent;
    }

    /**
     * Decides whether the specified byte array is a DER tag for a private key
     * object.
     *
     * @param tag The tag.
     *
     * @return true if the specified tag represents a private key object, false
     *         otherwise.
     */
    private boolean isPrivateKeyTag(byte[] tag) {
        return Arrays.equals(tag, TLV_TAG_PRIVATE_KEY);
    }

    /**
     * Decides whether the specified byte array is a DER tag for a public key
     * object.
     *
     * @param tag The tag.
     *
     * @return true if the specified tag represents a public key object, false
     *         otherwise.
     */
    private boolean isPublicKeyTag(byte[] tag) {
        return Arrays.equals(tag, TLV_TAG_PUBLIC_KEY)
                || Arrays.equals(tag, TLV_TAG_PUBLIC_KEY_TRUSTED);
    }

    /**
     * Decides whether the specified byte array is a DER tag for a certificate
     * object.
     *
     * @param tag The tag.
     *
     * @return true if the specified tag represents a certificate object, false
     *         otherwise.
     */
    private boolean isCertificateTag(byte[] tag) {
        return Arrays.equals(tag, TLV_TAG_CERTIFICATE)
                || Arrays.equals(tag, TLV_TAG_CERTIFICATE_TRUSTED)
                || Arrays.equals(tag, TLV_TAG_CERTIFICATE_USEFUL);
    }

    /**
     * Decides whether the specified byte array is a DER tag for a data
     * object.
     *
     * @param tag The tag.
     *
     * @return true if the specified tag represents a data object, false
     *         otherwise.
     */
    private boolean isDataObjectTag(byte[] tag) {
        return Arrays.equals(tag, TLV_TAG_DATA_OBJECT);
    }

    /**
     * Decides whether the specified byte array is a DER tag for an
     * authentication object.
     *
     * @param tag The tag.
     *
     * @return true if the specified tag represents an authentication object,
     *         false otherwise.
     */
    private boolean isAuthenticationObjectTag(byte[] tag) {
        return Arrays.equals(tag, TLV_TAG_AUTHENTICATE_OBJECT);
    }
}
