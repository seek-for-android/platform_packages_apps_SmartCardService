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

import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import dalvik.system.DexClassLoader;

/**
 * The smartcard service is setup with privileges to access smart card hardware.
 * The service enforces the permission
 * 'org.simalliance.openmobileapi.SMARTCARD'.
 */
public final class SmartcardService extends Service {

    public static final String LOG_TAG = "SmartcardService";

    /**
     * For now this list is setup in onCreate(), not changed later and therefore
     * not synchronized.
     */
    private Map<String, Terminal> mTerminals = new TreeMap<>();

    public SmartcardService() {
        super();
    }

    @Override
    public IBinder onBind(Intent intent) {
        Log.v(LOG_TAG, Thread.currentThread().getName() + " smartcard service onBind");
        if ("org.simalliance.openmobileapi.BIND_SERVICE".equals(intent.getAction())) {
            return new SmartcardServiceBinder();
        }
        return null;
    }

    @Override
    public void onCreate() {
        Log.v(LOG_TAG, Thread.currentThread().getName() + " smartcard service onCreate");
        createTerminals();
    }

    @Override
    public void dump(FileDescriptor fd, PrintWriter writer, String[] args) {
        writer.println("SMARTCARD SERVICE (dumpsys activity "
                + "service org.simalliance.openmobileapi)");
        writer.println();

        String prefix = "  ";

        if (!Build.IS_DEBUGGABLE) {
            writer.println(prefix + "Your build is not debuggable!");
            writer.println(prefix + "Smartcard service dump is only available"
                    + "for userdebug and eng build");
        } else {
            writer.println(prefix + "List of terminals:");
            for (Terminal terminal : mTerminals.values()) {
                writer.println(prefix + "  " + terminal.getName());
            }
            writer.println();

            for (Terminal terminal : mTerminals.values()) {
                terminal.dump(writer, prefix);
            }
        }
    }

    public void onDestroy() {
        Log.v(LOG_TAG, " smartcard service onDestroy ...");
        for (Terminal terminal : mTerminals.values()) {
            terminal.onSmartcardServiceShutdown();
        }

        Log.v(LOG_TAG, Thread.currentThread().getName()
                + " ... smartcard service onDestroy");

    }

    private ISmartcardServiceReader getReader(String reader) {
        if (reader == null) {
            throw new NullPointerException("Reader must not be null");
        }
        Terminal terminal = mTerminals.get(reader);
        if (terminal == null) {
            throw new IllegalArgumentException("Unknown reader");
        }
        return terminal.getBinder();
    }

    /**
     * Checks if a terminal is valid or not. The policy is the following:
     * - Terminal must require the org.simalliance.openmobileapi.BIND_TERMINAL permission. This is
     *   to make sure that only SmartcardService can bind to it, so third-party apps cannot bypass
     *   SmartcardService.
     * - If terminal type is SIM, eSE or SD (i.e., is a "system" terminal), it must declare the
     *   org.simalliance.openmobileapi.SYSTEM_TERMINAL permission. This is to avoid that a malware
     *   app can impersonate a system terminal.
     *
     * @param terminalType The type of the terminal being used.
     * @param resolveInfo The information we have about the terminal.
     *
     * @return True if the terminal is valid, false otherwise.
     *
     * @throws PackageManager.NameNotFoundException If the package name could not be located.
     */
    private boolean isValidTerminal(String terminalType, ResolveInfo resolveInfo)
            throws PackageManager.NameNotFoundException {
        // Get terminal type
        String packageName = resolveInfo.serviceInfo.applicationInfo.packageName;
        Log.d(LOG_TAG, "Check if "+ packageName + " contains a valid Terminal");
        PackageInfo packageInfo = getPackageManager().getPackageInfo(
                                                    packageName, PackageManager.GET_PERMISSIONS);
        // Check that terminal service requires the appropriate permission
        if (!"org.simalliance.openmobileapi.BIND_TERMINAL".equals(resolveInfo.serviceInfo.permission)) {
            Log.w(LOG_TAG, "Terminal does not require BIND_TERMINAL permission");
            return false;
        }
        if ("SIM".equalsIgnoreCase(terminalType)
                || "eSE".equalsIgnoreCase(terminalType)
                || "SD".equalsIgnoreCase(terminalType)) {
            String[] requestedPermissions = packageInfo.requestedPermissions;
            for(String permission : requestedPermissions) {
                if("org.simalliance.openmobileapi.SYSTEM_TERMINAL".equals(permission)) {
                    return true;
                }
            }
            Log.w(LOG_TAG, terminalType + "terminal does not declare SYSTEM_TERMINAL permission");
            return false;
        }
        return true;
    }

    /**
     * Finds all the terminals that are present on the system and adds them to the mTerminals map.
     * or a terminal to be discovered, it must listen to the
     * org.simalliance.openmobileapi.TERMINAL_DISCOVERY intent.
     */
    private void createTerminals() {
        // Find Terminal packages
        PackageManager pm = getApplicationContext().getPackageManager();
        List<ResolveInfo> terminallist = pm.queryIntentServices(
                new Intent("org.simalliance.openmobileapi.TERMINAL_DISCOVERY"),
                PackageManager.GET_INTENT_FILTERS);
        Log.d(LOG_TAG, "Found " + terminallist.size() + " terminals.");
        for (ResolveInfo info : terminallist) {
            try {
                String terminalType = (String) info.loadLabel(pm);
                if (!isValidTerminal(terminalType, info)) {
                    Log.w(LOG_TAG, "Invalid Terminal of type " + terminalType + ", not added");
                    continue;
                }
                String name = terminalType + getIndexForTerminal(terminalType);
                Log.d(LOG_TAG, "Adding terminal " + name);
                mTerminals.put(name, new Terminal(SmartcardService.this, name, info));
            } catch (Exception e) {
                Log.e(LOG_TAG, Thread.currentThread().getName()
                        + " CreateReaders Error: "
                        + ((e.getMessage() != null) ? e.getMessage()
                        : "unknown"), e);
            }
        }
    }

    private String[] createTerminalNamesList() {
        Set<String> names = mTerminals.keySet();
        ArrayList<String> list = new ArrayList<>(names);

        return list.toArray(new String[list.size()]);
    }

    /**
     * Computes the index that should be assigned to each terminal.
     *
     * @param type of the terminal to compute the index for.
     *
     * @return The index that shall be assigned to the given terminal.
     */
    private int getIndexForTerminal(String type) {
        return getTerminalsOfType(type).length + 1;
    }

    /**
     * Returns an array of terminals of the specified type (SIM/eSE/SD/...).
     *
     * @param terminalType The type of the terminals to be retrieved.
     *
     * @return An array of terminals of the specified type.
     */
    private Terminal[] getTerminalsOfType(String terminalType) {
        ArrayList<Terminal> terminals = new ArrayList<>();
        int index = 1;
        String name = terminalType + index;
        while (mTerminals.containsKey(name)) {
            terminals.add(mTerminals.get(name));
            index++;
            name = terminalType + index;
        }

        return terminals.toArray(new Terminal[terminals.size()]);
    }

    /**
     * The smartcard service interface implementation.
     */
    private class SmartcardServiceBinder extends ISmartcardService.Stub {

        @Override
        public String[] getReaders() throws RemoteException {
            return createTerminalNamesList();
        }

        @Override
        public ISmartcardServiceReader getReader(String reader, SmartcardError error) throws RemoteException {
            try {
                return SmartcardService.this.getReader(reader);
            } catch (Exception e) {
                Log.e(SmartcardService.LOG_TAG, "Error during getReader()", e);
                error.set(e);
                return null;
            }
        }
    }
}
