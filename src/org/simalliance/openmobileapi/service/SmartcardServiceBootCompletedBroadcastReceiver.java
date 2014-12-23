
package org.simalliance.openmobileapi.service;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class SmartcardServiceBootCompletedBroadcastReceiver extends BroadcastReceiver {
	public final static String _TAG = "SmartcardService";

	@Override
	public void onReceive(Context context, Intent intent) {
	    final boolean bootCompleted = intent.getAction().equals("android.intent.action.BOOT_COMPLETED");
   
        Log.v(_TAG, Thread.currentThread().getName() + " Received broadcast");
	    if( bootCompleted ){
	    	Log.v(_TAG, "Starting smartcard service after boot completed");
	    	Intent serviceIntent = new Intent(context, org.simalliance.openmobileapi.service.SmartcardService.class );
	    	context.startService(serviceIntent);
	    } else {
	    	
	    }
	}
};
