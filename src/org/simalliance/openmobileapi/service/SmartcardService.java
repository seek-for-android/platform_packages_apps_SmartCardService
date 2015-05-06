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
 * 'org.simalliance.openmobileapi.service.permission.BIND'.
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
        if (ISmartcardService.class.getName().equals(intent.getAction())) {
            return mSmartcardBinder;
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

    private boolean isValidTerminal(String packageName, String terminalType) throws PackageManager.NameNotFoundException {
        Log.d(LOG_TAG, "Check if "+ terminalType + " is a valid Terminal");
        if ("SIM".equalsIgnoreCase(terminalType) || "eSE".equalsIgnoreCase(terminalType) || "SD".equalsIgnoreCase(terminalType)) {
            String[] permissions = getPackageManager().getPackageInfo(packageName, PackageManager.GET_PERMISSIONS).requestedPermissions;
            for(String permission : permissions) {
                if("org.simalliance.openmobileapi.SYSTEM_TERMINAL".equals(permission)) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    private void createTerminals() {
        // Find Terminal packages
        PackageManager pm = getApplicationContext().getPackageManager();
        List<ResolveInfo> terminallist = pm.queryIntentServices(
                new Intent("org.simalliance.openmobileapi.TERMINAL_DISCOVERY"),
                PackageManager.GET_INTENT_FILTERS);
        Log.d(LOG_TAG, "Found " + terminallist.size() + " terminals.");
        for (ResolveInfo info : terminallist) {
            try {
                String packageName = info.serviceInfo.applicationInfo.packageName;
                String sourceDir = getPackageManager().getApplicationInfo(packageName, 0).sourceDir;
                DexClassLoader cl = new DexClassLoader(
                            sourceDir,
                            getCacheDir().getAbsolutePath(),
                            null,
                            ClassLoader.getSystemClassLoader().getParent());
                String terminalType = (String) cl
                        .loadClass(info.serviceInfo.name)
                        .getMethod("getType", (Class<?>[]) null)
                        .invoke(null, (Object[]) null);
                if (!isValidTerminal(packageName, terminalType)) {
                    Log.d(LOG_TAG, "Invalid Terminal, not added");
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

    // TODO: move this to an inner, named class
    /**
     * The smartcard service interface implementation.
     */
    private final ISmartcardService.Stub mSmartcardBinder
        = new ISmartcardService.Stub() {

        @Override
        public String[] getReaders(SmartcardError error) throws RemoteException {
            try {
                return createTerminalNamesList();
            } catch (Exception e) {
                Log.e(SmartcardService.LOG_TAG, "Error during getReaders()", e);
                error.set(e);
                return null;
            }
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
    };
}
