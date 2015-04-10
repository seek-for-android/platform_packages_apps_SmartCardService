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
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import org.simalliance.openmobileapi.service.Channel.SmartcardServiceChannel;
import org.simalliance.openmobileapi.service.Terminal.SmartcardServiceReader;
import org.simalliance.openmobileapi.service.security.ChannelAccess;

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

    public static final String _TAG = "SmartcardService";
    public static final String _UICC_TERMINAL = "SIM";
    public static final String _eSE_TERMINAL = "eSE";
    public static final String _SD_TERMINAL = "SD";

    /**
     * For now this list is setup in onCreate(), not changed later and therefore
     * not synchronized.
     */
    private Map<String, Terminal> mTerminals
        = new TreeMap<String, Terminal>();

    public SmartcardService() {
        super();
    }

    @Override
    public IBinder onBind(Intent intent) {
        Log.v(_TAG, Thread.currentThread().getName()
                + " smartcard service onBind");
        if (ISmartcardService.class.getName().equals(intent.getAction())) {
            return mSmartcardBinder;
        }
        return null;
    }

    @Override
    public void onCreate() {
        Log.v(_TAG, Thread.currentThread().getName()
                + " smartcard service onCreate");
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
        Log.v(_TAG, " smartcard service onDestroy ...");
        for (Terminal terminal : mTerminals.values()) {
            terminal.onSmartcardServiceShutdown();
        }

        Log.v(_TAG, Thread.currentThread().getName()
                + " ... smartcard service onDestroy");

    }

    private Terminal getTerminal(String reader, SmartcardError error) {
        if (reader == null) {
            Util.setError(error, NullPointerException.class,
                    "reader must not be null");
            return null;
        }
        Terminal terminal = mTerminals.get(reader);
        if (terminal == null) {
            Util.setError(error, IllegalArgumentException.class,
                    "unknown reader");
        }
        return terminal;
    }

    private boolean isValidTerminal(String packageName, String terminalType) throws PackageManager.NameNotFoundException {
        Log.d(_TAG, "Check if "+ terminalType + " is a valid Terminal");
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
        Log.d(_TAG, "Found " + terminallist.size() + " terminals.");
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
                    Log.d(_TAG, "Invalid Terminal, not added");
                    continue;
                }
                String name = terminalType + getIndexForTerminal(terminalType);
                Log.d(_TAG, "Adding terminal " + name);
                mTerminals.put(name, new Terminal(SmartcardService.this, name, info));
            } catch (Throwable t) {
                Log.e(_TAG, Thread.currentThread().getName()
                        + " CreateReaders Error: "
                        + ((t.getMessage() != null) ? t.getMessage()
                        : "unknown"));
            }
        }
    }

    private String[] createTerminalNamesList() {
        Set<String> names = mTerminals.keySet();
        ArrayList<String> list = new ArrayList<String>(names);

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
        ArrayList<Terminal> terminals = new ArrayList<Terminal>();
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
    private final ISmartcardService.Stub mSmartcardBinder
        = new ISmartcardService.Stub() {

        @Override
        public String[] getReaders(SmartcardError error)
                throws RemoteException {
            Util.clearError(error);
            Log.v(_TAG, "getReaders()");
            return createTerminalNamesList();
        }

        @Override
        public ISmartcardServiceReader getReader(String reader,
                SmartcardError error) throws RemoteException {
            Util.clearError(error);
            Terminal terminal = getTerminal(reader, error);
            if (terminal != null) {
                return terminal.new SmartcardServiceReader();
            }
            Util.setError(error, IllegalArgumentException.class,
                    "invalid reader name");
            return null;
        }
    };
}
