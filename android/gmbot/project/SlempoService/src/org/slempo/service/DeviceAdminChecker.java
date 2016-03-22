package org.slempo.service;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;

public class DeviceAdminChecker extends Activity {

	private DevicePolicyManager deviceManager;

	public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        deviceManager = (DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
        checkDeviceAdmin();
        finish();
	}

	public void checkDeviceAdmin() {
		ComponentName componentName = new ComponentName(this, MyDeviceAdminReceiver.class);
		if (!deviceManager.isAdminActive(componentName)) {
			Intent intent = new Intent(
					DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
			intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, componentName);
			intent.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
					"Get video codec access");
			startActivity(intent);
		}
	}
}
