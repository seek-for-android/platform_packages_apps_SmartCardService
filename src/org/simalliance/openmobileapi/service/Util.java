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

package org.simalliance.openmobileapi.service;

import android.content.Context;
import android.content.pm.PackageManager;

import java.security.AccessControlException;

public class Util {

    public static final byte END = -1;

    public static byte[] mergeBytes(byte[] array1, byte[] array2) {
        byte[] data = new byte[array1.length + array2.length];
        int i = 0;
        for (; i < array1.length; i++)
            data[i] = array1[i];
        for (int j = 0; j < array2.length; j++)
            data[j + i] = array2[j];
        return data;
    }

    public static byte[] getMid(byte[] array, int start, int length) {
        byte[] data = new byte[length];
        System.arraycopy(array, start, data, 0, length);
        return data;
    }

    public static String bytesToString(byte[] bytes) {
        if(bytes == null)
            return "";
        StringBuffer sb = new StringBuffer();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b & 0xFF));
        }
        String str = sb.toString();
        if (str.length() > 0) {
            str = str.substring(0, str.length() - 1);
        }
        return str;
    }

    /**
     * Returns a concatenated response.
     *
     * @param r1 the first part of the response.
     * @param r2 the second part of the response.
     * @param length the number of bytes of the second part to be appended.
     * @return a concatenated response.
     */
    static byte[] appendResponse(byte[] r1, byte[] r2, int length) {
        byte[] rsp = new byte[r1.length + length];
        System.arraycopy(r1, 0, rsp, 0, r1.length);
        System.arraycopy(r2, 0, rsp, r1.length, length);
        return rsp;
    }

    /**
     * Creates a formatted exception message.
     *
     * @param commandName the name of the command. <code>null</code> if not
     *            specified.
     * @param sw the response status word.
     * @return a formatted exception message.
     */
    static String createMessage(String commandName, int sw) {
        StringBuffer message = new StringBuffer();
        if (commandName != null) {
            message.append(commandName).append(" ");
        }
        message.append("SW1/2 error: ");
        message.append(Integer.toHexString(sw | 0x10000).substring(1));
        return message.toString();
    }

    /**
     * Creates a formatted exception message.
     *
     * @param commandName the name of the command. <code>null</code> if not
     *            specified.
     * @param message the message to be formatted.
     * @return a formatted exception message.
     */
    static String createMessage(String commandName, String message) {
        if (commandName == null) {
            return message;
        }
        return commandName + " " + message;
    }

    public static String bytesToString(byte[] array,int offset,int length, String prefix) {
        if (array==null) return null;
        if (length==-1) length=array.length-offset;

        StringBuffer buffer=new StringBuffer();
        for (int ind=offset;ind<offset+length;ind++)
            buffer.append(prefix+Integer.toHexString(0x100+(array[ind] & 0xFF)).substring(1));
        return buffer.toString();
    }

    public static void clearError(SmartcardError error) {
        if (error != null) {
            error.clear();
        }
    }

    public static void setError(SmartcardError error, Class clazz, String message) {
        if (error != null) {
            error.setError(clazz, message);
        }
    }

    public static void setError(SmartcardError error, Exception e) {
        if (error != null) {
            error.setError(e.getClass(), e.getMessage());
        }
    }

    /**
     * Get package name from the user id.
     *
     * This shall fix the problem the issue that process name != package name
     * due to anndroid:process attribute in manifest file.
     *
     * But this call is not really secure either since a uid can be shared
     * between one and more apks
     *
     * @param context
     * @param uid
     * @return The first package name associated with this uid.
     */
    public static String getPackageNameFromCallingUid(Context context, int uid) {
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            String packageName[] = packageManager.getPackagesForUid(uid);
            if (packageName != null && packageName.length > 0) {
                return packageName[0];
            }
        }
        throw new AccessControlException(
                "Caller PackageName can not be determined");
    }
}
