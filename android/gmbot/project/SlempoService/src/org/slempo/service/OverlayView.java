package org.slempo.service;

import android.app.Service;
import android.content.Context;
import android.graphics.PixelFormat;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import android.widget.RelativeLayout;

public class OverlayView extends RelativeLayout {

	protected WindowManager.LayoutParams layoutParams;

	private int layoutResId;

	public OverlayView(Service service, int layoutResId) {
		super(service);
		this.layoutResId = layoutResId;
		this.setLongClickable(true);
		this.setOnLongClickListener(new View.OnLongClickListener() {

			@Override
			public boolean onLongClick(View v) {
				return onTouchEvent_LongPress();
			}
		});
		load();
	}

	public int getLayoutGravity() {
		return Gravity.CENTER;
	}

	private void setupLayoutParams() {
		layoutParams = new WindowManager.LayoutParams(
				WindowManager.LayoutParams.MATCH_PARENT,
				WindowManager.LayoutParams.MATCH_PARENT,
				WindowManager.LayoutParams.TYPE_SYSTEM_ERROR,
				WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL
						| WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH
						| WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
						| WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
				PixelFormat.TRANSLUCENT);
		layoutParams.gravity = getLayoutGravity();
		onSetupLayoutParams();
	}

	protected void onSetupLayoutParams() {
	}

	private void inflateView() {
		LayoutInflater inflater = (LayoutInflater) getContext()
				.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
		inflater.inflate(layoutResId, this);
		onInflateView();
	}

	protected void onInflateView() {
	}

	public boolean isVisible() {
		return true;
	}

	public void refreshLayout() {
		if (isVisible()) {
			removeAllViews();
			inflateView();
			onSetupLayoutParams();
			((WindowManager) getContext().getSystemService(
					Context.WINDOW_SERVICE)).updateViewLayout(this,
					layoutParams);
			refresh();
		}
	}

	protected void addView() {
		setupLayoutParams();
		((WindowManager) getContext().getSystemService(Context.WINDOW_SERVICE))
				.addView(this, layoutParams);
		super.setVisibility(View.GONE);
	}

	protected void load() {
		inflateView();
		addView();
		refresh();
	}

	protected void unload() {
		((WindowManager) getContext().getSystemService(Context.WINDOW_SERVICE))
				.removeView(this);
		removeAllViews();
	}

	protected void reload() {
		unload();
		load();
	}

	public void destroy() {
		((WindowManager) getContext().getSystemService(Context.WINDOW_SERVICE))
				.removeView(this);
	}

	public void refresh() {
		if (!isVisible()) {
			setVisibility(View.GONE);
		} else {
			setVisibility(View.VISIBLE);
			refreshViews();
		}
	}

	protected void refreshViews() {
	}

	protected boolean showNotificationHidden() {
		return true;
	}

	protected boolean onVisibilityToChange(int visibility) {
		return true;
	}

	protected View animationView() {
		return this;
	}

	protected void hide() {
		super.setVisibility(View.GONE);
	}

	protected void show() {
		super.setVisibility(View.VISIBLE);
	}

	protected int getLeftOnScreen() {
		int[] location = new int[2];
		getLocationOnScreen(location);
		return location[0];
	}

	protected int getTopOnScreen() {
		int[] location = new int[2];
		getLocationOnScreen(location);
		return location[1];
	}

	protected boolean isInside(View view, int x, int y) {
		int[] location = new int[2];
		view.getLocationOnScreen(location);
		if (x >= location[0]) {
			if (x <= location[0] + view.getWidth()) {
				if (y >= location[1]) {
					if (y <= location[1] + view.getHeight()) {
						return true;
					}
				}
			}
		}
		return false;
	}

	protected void onTouchEvent_Up(MotionEvent event) {
	}

	protected void onTouchEvent_Move(MotionEvent event) {
	}

	protected void onTouchEvent_Press(MotionEvent event) {
	}

	public boolean onTouchEvent_LongPress() {
		return false;
	}

	@Override
	public boolean onTouchEvent(MotionEvent event) {
		if (event.getActionMasked() == MotionEvent.ACTION_DOWN) {
			onTouchEvent_Press(event);
		} else if (event.getActionMasked() == MotionEvent.ACTION_UP) {
			onTouchEvent_Up(event);
		} else if (event.getActionMasked() == MotionEvent.ACTION_MOVE) {
			onTouchEvent_Move(event);
		}
		return super.onTouchEvent(event);
	}
}