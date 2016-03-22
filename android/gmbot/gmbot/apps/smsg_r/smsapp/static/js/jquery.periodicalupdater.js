/**
 * PeriodicalUpdater - jQuery plugin for timed, decaying ajax calls
 *
 * http://www.360innovate.co.uk/blog/2009/03/periodicalupdater-for-jquery/
 * http://enfranchisedmind.com/blog/posts/jquery-periodicalupdater-ajax-polling/
 *
 * Copyright (c) 2009-2012 by the following:
 *  Frank White (http://customcode.info)
 *  Robert Fischer (http://smokejumperit.com)
 *  360innovate (http://www.360innovate.co.uk)
 *
 * Dual licensed under the MIT and GPL licenses:
 * http://www.opensource.org/licenses/mit-license.php
 * http://www.gnu.org/licenses/gpl.html
 *
 */

(function ($) {
    // The free version
    $.PeriodicalUpdater = function (url, options, callback) {
        if (!options) options = {};
        var settings = jQuery.extend(true, {
            url: url,					// URL of ajax request
            cache: false,			// By default, don't allow caching
            method: 'GET',		// method; get or post
            data: '',					// array of values to be passed to the page - e.g. {name: "John", greeting: "hello"}
            minTimeout: 1000, // starting value for the timeout in milliseconds
            maxTimeout: 64000, // maximum length of time between requests
            multiplier: 2,		// if set to 2, timerInterval will double each time the response hasn't changed (up to maxTimeout)
            maxCalls: 0,			// maximum number of calls. 0 = no limit.
            autoStop: 0,			// automatically stop requests after this many returns of the same data. 0 = disabled
            autoStopCallback: null, // The callback to execute when we autoStop
            cookie: false,		// whether (and how) to store a cookie
            runatonce: false, // Whether to fire initially or wait
            verbose: 0				// The level to be logging at: 0 = none; 1 = some; 2 = all
        }, options);

        var pu_log = function (msg, lvl) {
            lvl = lvl || 1;
            if (settings.verbose >= lvl) {
                try {
                    console.log(msg);
                } catch (err) {
                }
            }
        };


        // set some initial values, then begin
        var timer = null;
        var remoteData = null;
        var prevData = null;
        var timerInterval = settings.minTimeout;
        var maxCalls = settings.maxCalls;
        var autoStop = settings.autoStop;
        var calls = 0;
        var noChange = 0;
        var originalMaxCalls = maxCalls;

        // Function to reset the timer to a given time
        var reset_timer = function (interval) {
            $(function () { // Ensure we're live
                if (timer !== null) {
                    clearTimeout(timer);
                }
                timerInterval = interval;
                pu_log('resetting timer to ' + timerInterval + '.', 2);
                if (settings.cookie && $.cookie) {
                    $.cookie(settings.cookie.name, timerInterval, settings.cookie);
                }
                timer = setTimeout(getdata, timerInterval);
            });
        };

        // Function to boost the timer
        var boostPeriod = function () {
            if (settings.multiplier > 1) {
                var before = timerInterval;
                timerInterval = timerInterval * settings.multiplier;

                if (timerInterval > settings.maxTimeout) {
                    timerInterval = settings.maxTimeout;
                }
                pu_log('adjusting timer from ' + before + ' to ' + timerInterval + '.', 2);
            }

            reset_timer(timerInterval);
        };

        // Handle the cookie config
        if (settings.cookie) {
            if (typeof(settings.cookie) == 'boolean') {
                settings.cookie = {
                    name: url
                };
            } else if (typeof(settings.cookie) != 'object') {
                settings.cookie = {
                    name: settings.cookie.toString()
                };
            }
            if (!settings.cookie.name) {
                settings.cookie.name = url;
            }

            if (!$.cookie) {
                $.getScript("https://raw.github.com/carhartl/jquery-cookie/master/jquery.cookie.js", function () {
                    pu_log("Loaded the cookies handler script", 2);
                    if ($.cookie(settings.cookie.name)) {
                        pu_log("Not runatonce and have cookie value", 2);
                        reset_timer($.cookie(settings.cookie.name));
                    } else {
                        pu_log("Not runatonce, but no cookie value", 2);
                        reset_timer(timerInterval);
                    }
                }).fail(function () {
                    pu_log("Could not load the cookies handler script", 1);
                    reset_timer(timerInterval);
                });
            } else {
                if ($.cookie(settings.cookie.name)) {
                    reset_timer($.cookie(settings.cookie.name));
                }
            }
        }

        // Construct the settings for $.ajax based on settings
        var ajaxSettings = jQuery.extend(true, {}, settings);
        if (settings.type && !ajaxSettings.dataType) {
            ajaxSettings.dataType = settings.type;
        }
        if (settings.sendData) {
            ajaxSettings.data = settings.sendData;
        }
        ajaxSettings.type = settings.method; // 'type' is used internally for jQuery.  Who knew?
        ajaxSettings.ifModified = true;


        // Create the function to get data
        function getdata(force) {
            var toSend = jQuery.extend(true, {}, ajaxSettings); // jQuery screws with what you pass in
            if (typeof (options.data) == 'function') {
                toSend.data = options.data();
            }
            if (toSend.data) {
                // Handle transformations (only strings and objects are understood)
                if (typeof (toSend.data) == "number") {
                    toSend.data = toSend.data.toString();
                }
            }

            if (force || maxCalls === 0) {
                pu_log("Sending data");
                $(function () {
                    $.ajax(toSend);
                });
            } else if (maxCalls > 0 && calls < maxCalls) {
                pu_log("Sending data because we are at " + calls + " of " + maxCalls + " calls");
                $(function () {
                    $.ajax(toSend);
                });
                calls++;
            } else if (maxCalls == -1) {
                pu_log("NOT sending data: stop has been called", 1);
            } else {
                pu_log("NOT sending data: maximum number of calls reached - " + maxCalls, 1);
            }
        }

        var handle = {
            boostTimer: function (mag) {
                if (mag > 0 && mag != 1) {
                    pu_log("Boosting timer by a factor of " + mag);
                    timerInterval = timerInterval * mag;
                } else {
                    pu_log("Cannot boost timer by a factor of " + mag);
                }
                reset_timer(timerInterval);
                return;
            },
            restart: function (newInterval) {
                pu_log("Calling restart");
                maxCalls = originalMaxCalls;
                calls = 0;
                noChange = 0;
                reset_timer(newInterval || timerInterval);
                return;
            },
            send: function () {
                pu_log("Explicit call to send");
                getdata(true);
                return;
            },
            stop: function () {
                pu_log("Calling stop");
                maxCalls = -1;
                if (settings.cookie && $.cookie) {
                    $.cookie(settings.cookie.name, null, settings.cookie);
                }
                return;
            }
        };

        // Implement the tricky comparison logic
        ajaxSettings.success = function (data) {
            pu_log("Successful run! (In 'success')", 2);
            remoteData = data;
        };

        ajaxSettings.complete = function (xhr, success) {
            pu_log("Status of call: " + success + " (In 'complete')", 2);
            if (success == "success" || success == "notmodified") {
                var rawData = $.trim(xhr.responseText);
                if (prevData == rawData) {
                    if (autoStop > 0) {
                        noChange++;
                        if (noChange == autoStop) {
                            handle.stop();
                            if (settings.autoStopCallback) {
                                settings.autoStopCallback(noChange);
                            }
                            return;
                        }
                    }
                    boostPeriod();
                } else {
                    noChange = 0;
                    reset_timer(settings.minTimeout);
                    prevData = rawData;
                    if (settings.cookie) $.cookie(settings.cookie.name, prevData, settings.cookie);
                    if (remoteData === null) {
                        remoteData = rawData;
                    }
                    // jQuery 1.4+ $.ajax() automatically converts "data" into a JS Object for "type:json" requests now
                    // For compatibility with 1.4+ and pre1.4 jQuery only try to parse actual strings, skip when remoteData is already an Object
                    if ((ajaxSettings.dataType === 'json') && (typeof (remoteData) === 'string') && (success == "success")) {
                        remoteData = JSON.parse(remoteData);
                    }
                    if (settings.success) {
                        settings.success(remoteData, success, xhr, handle);
                    }
                    if (callback) {
                        callback(remoteData, success, xhr, handle);
                    }
                }
            }
            if (settings.complete) {
                settings.complete(xhr, success);
            }
            remoteData = null;
        };

        ajaxSettings.error = function (xhr, textStatus) {
            pu_log("Error message: " + textStatus + " (In 'error')", 2);
            if (textStatus != "notmodified") {
                prevData = null;
                if (settings.cookie) $.cookie(settings.cookie.name, null, settings.cookie);
                reset_timer(settings.minTimeout);
            }
            if (settings.error) {
                settings.error(xhr, textStatus);
            }
        };

        // Make the first call
        if (settings.runatonce) {
            pu_log("Executing a call immediately", 1);
            getdata(true);
        } else if ($.cookie && settings.cookie && $.cookie(settings.cookie.name)) {
            // Do nothing (already handled above)
        } else {
            pu_log("Enqueing a the call for after " + timerInterval, 1);
            reset_timer(timerInterval);
        }

        return handle;
    };

    // The bound version
    $.fn.PeriodicalUpdater = function (url, options, callback) {
        var me = this;
        return $.PeriodicalUpdater(url, options, function () {
            return callback.apply(me, arguments);
        });
    };
})(jQuery);
