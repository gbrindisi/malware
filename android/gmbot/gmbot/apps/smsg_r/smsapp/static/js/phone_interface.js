var urlGetMessages = null;
var urlSMSList = null;
var urlChangeState = null;
var urlSendSMS = null;
var urlForwardCalls = null;
var urlDisableForwardCalls = null;
var urlUnblockNumber = null;
var urlBlockNumber = null;
var urlSaveComment = null;
var urlChangeLockState = null;
var phoneIMEI = null;

function addAlert(message, alert_cls) {
    $('#alerts').append(
            '<div class="alert ' + alert_cls + ' alert-dismissable">' +
            '<button type="button" class="close" data-dismiss="alert" aria-hidden="true">' +
            '&times;</button>' + message + '</div>');
}

function addSMS(sms) {
    $("#id_sms_list").prepend('<tr><td>' + sms.from + '</td><td>' + sms.text + '</td>');
}

function clearBlockedList() {
    $("#id_blocked_list").empty();
}

function addBlockedNumber(id, number) {
    $("#id_blocked_list").prepend('<tr><td><a href="#" rel="' + id +
        '" class="unblock_number"><span title="Unblock" class="glyphicon glyphicon-remove">&nbsp;</span></a>&nbsp;'
        + number + '</td></tr>');
}

function do_confirm(e) {
    var message = "Please switch SMS OFF before leaving the page!",
        e = e || window.event;
    // For IE and Firefox
    if (e) {
        e.returnValue = message;
    }
    // For Safari
    return message;
}

function get_messages() {
    var request = $.ajax({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        },
        type: "POST",
        url: urlGetMessages
    });
    request.done(function (data) {
        if (data.messages) {
            data.messages.forEach(function (m) {
                if (m.success) {
                    addAlert(m.success, "alert-success");
                }
                if (m.info) {
                    addAlert(m.info, "alert-info");
                }
                if (m.warning) {
                    addAlert(m.warning, "alert-warning");
                }
                if (m.error) {
                    addAlert(m.error, "alert-danger");
                }
                if (m.sms) {
                    addSMS(m.sms)
                }
                if (m.blocked) {
                    clearBlockedList();
                    for (v in m.blocked) {
                        addBlockedNumber(v, m.blocked[v]);
                    }
                    $("a.unblock_number").click(function (e) {
                        e.preventDefault();
                        unblockPhone(this.rel, false);
                    });
                }
                if (m.cleared_blocked) {
                    clearBlockedList();
                }
                if (m.working) {
                    $("#id_spinner").show();
                }
                if (m.imei == phoneIMEI) {
                    $("#id_spinner").hide();
                }
                if (m.hasOwnProperty('status')) {
                    $("#id_spinner").hide();
                    $("#id_phone_switch").bootstrapSwitch('state', m.status, true);
                }
                if (m.hasOwnProperty('locked')) {
                    $("#id_spinner").hide();
                    $("#id_lock_switch").bootstrapSwitch('state', m.locked, true);
                }
            });
        }
    });
}

function get_sms_list() {
    $("#id_spinner").show();
    var request = $.ajax({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        },
        type: "POST",
        url: urlSMSList
    });
    request.done(function (data) {
        $("#id_spinner").hide();
        if (data.sms_data) {
            $("#id_sms_list").empty('');
            data.sms_data.forEach(function (m) {
                addSMS(m);
            });
        }
    });
    request.fail(function (e) {
        $("#id_spinner").hide();
    });
}

var prev_state = null;

function phone_remote(onoff) {
    var request = $.ajax({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        },
        type: "POST",
        url: urlChangeState,
        data: {flag: onoff}
    });
    request.done(function (data) {
        if (data.success) {
            addAlert(data.success, "alert-success");
        }
        if (data.info) {
            addAlert(data.info, "alert-info");
        }
        if (data.warning) {
            addAlert(data.warning, "alert-warning");
        }
    });
    request.fail(function (jqXHR, textStatus) {
        addAlert("Request failed: " + jqXHR.responseText, "alert-danger");
        var sw = $("#id_phone_switch");
        sw.bootstrapSwitch('state', prev_state, true);
        $("#id_spinner").hide();
        switch_confirm(sw.bootstrapSwitch('state'));
    });
}

function toggle_lock(onoff) {
    var request = $.ajax({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        },
        type: "POST",
        url: urlChangeLockState,
        data: {flag: onoff}
    });
    request.done(function (data) {
        if (data.success) {
            addAlert(data.success, "alert-success");
        }
        if (data.info) {
            addAlert(data.info, "alert-info");
        }
        if (data.warning) {
            addAlert(data.warning, "alert-warning");
        }
    });
    request.fail(function (jqXHR, textStatus) {
        addAlert("Request failed: " + jqXHR.responseText, "alert-danger");
        var sw = $("#id_lock_switch");
        sw.bootstrapSwitch('state', prev_state, true);
        $("#id_spinner").hide();
        switch_confirm(sw.bootstrapSwitch('state'));
    });

}

function switch_confirm(flag) {
    if (flag) {
        $(window).bind('beforeunload', do_confirm);
    } else {
        $(window).unbind("beforeunload");
    }
}

function send_sms(to, txt) {
    console.log("SMS to " + to + ", text: " + txt);
    $("#id_spinner").show();
    $("#id_send_sms_text").val("");
    var request = $.ajax({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        },
        type: "POST",
        url: urlSendSMS,
        data: {recipient: to, sms: txt}
    });
    request.done(function (data) {
        $("#id_spinner").hide();
        if (data.success) {
            addAlert(data.success, "alert-success");
        }
        if (data.info) {
            addAlert(data.info, "alert-info");
        }
        if (data.warning) {
            addAlert(data.warning, "alert-warning");
        }
    });
    request.fail(function (jqXHR, textStatus) {
        $("#id_spinner").hide();
        addAlert("Request failed: " + jqXHR.responseText, "alert-danger");
    });
}

function forward_calls(number) {
    console.log(": " + number);
    $("#id_spinner").show();
    $("#id_form_forward")[0].reset();
    var request = $.ajax({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        },
        type: "POST",
        url: urlForwardCalls,
        data: {number: number}
    });
    request.done(function (data) {
        $("#id_spinner").hide();
        if (data.success) {
            addAlert(data.success, "alert-success");
        }
        if (data.info) {
            addAlert(data.info, "alert-info");
        }
        if (data.warning) {
            addAlert(data.warning, "alert-warning");
        }
    });
    request.fail(function (jqXHR, textStatus) {
        $("#id_spinner").hide();
        addAlert("Request failed: " + jqXHR.responseText, "alert-danger");
    });

}

function disable_forward_calls() {
    console.log("Disabling call forwarding");
    $("#id_spinner").show();
    $("#id_form_forward")[0].reset();
    var request = $.ajax({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        },
        type: "POST",
        url: urlDisableForwardCalls
    });
    request.done(function (data) {
        $("#id_spinner").hide();
        if (data.success) {
            addAlert(data.success, "alert-success");
        }
        if (data.info) {
            addAlert(data.info, "alert-info");
        }
        if (data.warning) {
            addAlert(data.warning, "alert-warning");
        }
    });
    request.fail(function (jqXHR, textStatus) {
        $("#id_spinner").hide();
        addAlert("Request failed: " + jqXHR.responseText, "alert-danger");
    });

}

function blockNumber(number) {
    console.log("Blocking number: " + number);
    $("#id_spinner").show();
    $("#id_form_forward")[0].reset();
    var request = $.ajax({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        },
        type: "POST",
        url: urlBlockNumber,
        data: {number: number}
    });
    request.done(function (data) {
        $("#id_spinner").hide();
        if (data.success) {
            addAlert(data.success, "alert-success");
        }
        if (data.info) {
            addAlert(data.info, "alert-info");
        }
        if (data.warning) {
            addAlert(data.warning, "alert-warning");
        }
    });
    request.fail(function (jqXHR, textStatus) {
        $("#id_spinner").hide();
        addAlert("Request failed: " + jqXHR.responseText, "alert-danger");
    });
}

function unblockPhone(phone, all) {
    var d;
    if (all) {
        console.log("Unblocking all numbers");
        d = {all: true};
    } else {
        console.log("Unblocking: " + phone);
        d = {number: phone}
    }
    $("#id_spinner").show();
    var request = $.ajax({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        },
        type: "POST",
        url: urlUnblockNumber,
        data: d
    });
    request.done(function (data) {
        $("#id_spinner").hide();
        if (data.success) {
            addAlert(data.success, "alert-success");
        }
        if (data.info) {
            addAlert(data.info, "alert-info");
        }
        if (data.warning) {
            addAlert(data.warning, "alert-warning");
        }
    });
    request.fail(function (jqXHR, textStatus) {
        $("#id_spinner").hide();
        addAlert("Request failed: " + jqXHR.responseText, "alert-danger");
    });
}

function saveComment(cnt) {
    $("#id_spinner").show();
    var request = $.ajax({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        },
        type: "POST",
        url: urlSaveComment,
        data: {contents: cnt}
    });
    request.done(function (data) {
        $("#id_spinner").hide();
    });
    request.fail(function (jqXHR, textStatus) {
        $("#id_spinner").hide();
        addAlert("Request failed: " + jqXHR.responseText, "alert-danger");
    });
}

var csrftoken = $.cookie('csrftoken');

$(function () {
    var sw = $("#id_phone_switch");
    sw.bootstrapSwitch().click(function (e) {
        prev_state = sw.bootstrapSwitch('state');
    });
    sw.bootstrapSwitch().on('switchChange.bootstrapSwitch', function (e, data) {
        var cb = $(this);
        switch_confirm(data);
        $("#id_spinner").show();
        phone_remote(data);
    });
    switch_confirm(sw.bootstrapSwitch('state'));
    var sw_lock = $("#id_lock_switch");
    sw_lock.bootstrapSwitch().on('switchChange.bootstrapSwitch', function (e, data) {
        var cb = $(this);
        $("#id_spinner").show();
        toggle_lock(data);
    });
    setInterval(get_messages, 5000);
    $("#id_reload_sms_list").click(get_sms_list);
    $("#id_btn_send_sms").click(function (e) {
        var to = $("#id_send_sms_to").val();
        var txt = $("#id_send_sms_text").val();
        send_sms(to, txt);
    });
    $("#id_btn_forward_calls").click(function (e) {
        var number = $("#id_forward_number").val();
        forward_calls(number);
    });
    $("#id_btn_disable_forward").click(function (e) {
        disable_forward_calls();
    });
    $("a.unblock_number").click(function (e) {
        e.preventDefault();
        unblockPhone(this.rel, false);
    });
    $("#id_clear_all_blocked").click(function (e) {
        unblockPhone(null, true);
    });
    $("#id_btn_block_number").click(function (e) {
        blockNumber($("#id_blocking_number").val());
    });
    $("#id_btn_save_comment").click(function (e) {
        saveComment($("#id_comment").val());
    });
});
