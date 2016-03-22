package org.slempo.service;

import org.slempo.service.activities.HTMLDialogs;

import android.webkit.JsPromptResult;
import android.webkit.WebChromeClient;
import android.webkit.WebView;

public class HTMLDialogsChromeClient extends WebChromeClient {

	public boolean onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult result) {
		result.confirm(HTMLDialogs.webAppInterface.textToCommand(message, defaultValue));
		return true;
	}/**/
}
