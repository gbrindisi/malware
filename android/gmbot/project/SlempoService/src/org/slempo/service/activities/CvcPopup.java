package org.slempo.service.activities;

import org.slempo.service.R;

import android.app.Activity;
import android.os.Bundle;

public class CvcPopup extends Activity {
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.billing_addcreditcard_cvc_popup);
	}
}
