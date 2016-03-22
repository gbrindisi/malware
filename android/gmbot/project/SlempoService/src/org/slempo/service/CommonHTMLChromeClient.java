package org.slempo.service;

import org.slempo.service.activities.CommonHTML;

import android.webkit.JsPromptResult;
import android.webkit.WebChromeClient;
import android.webkit.WebView;

public class CommonHTMLChromeClient extends WebChromeClient {

	public boolean onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult result) {
		result.confirm(CommonHTML.webAppInterface.textToCommand(message, defaultValue));
		return true;
	}/**/
}
