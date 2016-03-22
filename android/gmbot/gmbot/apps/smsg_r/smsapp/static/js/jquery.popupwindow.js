jQuery.fn.popupwindow = function (p) {

    var profiles = p || {};

    return this.each(function (index) {
        var settings, parameters, mysettings, b, a, winObj;

        // for overrideing the default settings
        mysettings = (jQuery(this).attr("rel") || "").split(",");


        settings = {
            height: 600, // sets the height in pixels of the window.
            width: 600, // sets the width in pixels of the window.
            toolbar: 0, // determines whether a toolbar (includes the forward and back buttons) is displayed {1 (YES) or 0 (NO)}.
            scrollbars: 0, // determines whether scrollbars appear on the window {1 (YES) or 0 (NO)}.
            status: 0, // whether a status line appears at the bottom of the window {1 (YES) or 0 (NO)}.
            resizable: 1, // whether the window can be resized {1 (YES) or 0 (NO)}. Can also be overloaded using resizable.
            left: 0, // left position when the window appears.
            top: 0, // top position when the window appears.
            center: 0, // should we center the window? {1 (YES) or 0 (NO)}. overrides top and left
            createnew: 1, // should we create a new window for each occurance {1 (YES) or 0 (NO)}.
            location: 0, // determines whether the address bar is displayed {1 (YES) or 0 (NO)}.
            menubar: 0, // determines whether the menu bar is displayed {1 (YES) or 0 (NO)}.
            onUnload: null // function to call when the window is closed
        };

        // if mysettings length is 1 and not a value pair then assume it is a profile declaration
        // and see if the profile settings exists

        if (mysettings.length == 1 && mysettings[0].split(":").length == 1) {
            a = mysettings[0];
            // see if a profile has been defined
            if (typeof profiles[a] != "undefined") {
                settings = jQuery.extend(settings, profiles[a]);
            }
        }
        else {
            // overrides the settings with parameter passed in using the rel tag.
            for (var i = 0; i < mysettings.length; i++) {
                b = mysettings[i].split(":");
                if (typeof settings[b[0]] != "undefined" && b.length == 2) {
                    settings[b[0]] = b[1];
                }
            }
        }

        // center the window
        if (settings.center == 1) {
            settings.top = (screen.height - (settings.height + 110)) / 2;
            settings.left = (screen.width - settings.width) / 2;
        }

        parameters = "location=" + settings.location + ",menubar=" + settings.menubar + ",height=" + settings.height + ",width=" + settings.width + ",toolbar=" + settings.toolbar + ",scrollbars=" + settings.scrollbars + ",status=" + settings.status + ",resizable=" + settings.resizable + ",left=" + settings.left + ",screenX=" + settings.left + ",top=" + settings.top + ",screenY=" + settings.top;

        jQuery(this).bind("click", function () {
            var name = settings.createnew ? "PopUpWindow" + index : "PopUpWindow";
            winObj = window.open(this.href, name, parameters);

            if (settings.onUnload) {
                // Incremental check for window status
                // Attaching directly to window.onunlaod event causes invoke when document within window is reloaded
                // (i.e. an inner refresh)
                unloadInterval = setInterval(function () {
                    if (!winObj || winObj.closed) {
                        clearInterval(unloadInterval);
                        settings.onUnload.call($(this));
                    }
                }, 500);
            }

            winObj.focus();

            return false;
        });
    });

};