//main.js
/*
/js
js/main.js << main file for require.js
--/libs/(jquery,backbone,etc.) << base libs
--/goatApp/ << base dir for goat application, js-wise
--/goatApp/model
--/goatApp/view
--/goatApp/support
--/goatApp/controller
*/

/**
 * Main configuration for RequireJS. Referred to from Spring MVC /start.mvc using main_new.html template.
 * baseURL is the base path of all JavaScript libraries.
 * paths refers to the JavaScript Libraries that we want to use. A name and relative path is used. Extension .js is not required.
 *
 * jquery is a library that can easily access all objects on the HTML page.
 * jquery-ui is an UI extension on jquery and adds stuff like dialog boxes.
 * underscore contains a library of helper methods.
 * backbone contains models, events, key value bindings. Depends on jQuery and underscore
 * polyglot is a tiny i18n helper library
 */
require.config({
  baseUrl: "js/",
  paths: {
    jquery: 'libs/jquery.min',
    jqueryvuln: 'libs/jquery-2.1.4.min',
    jqueryuivuln: 'libs/jquery-ui-1.10.4',
    jqueryui: 'libs/jquery-ui.min',
    underscore: 'libs/underscore-min',
    backbone: 'libs/backbone-min',
    bootstrap: 'libs/bootstrap.min',
    text: 'libs/text',
    templates: 'goatApp/templates',
    polyglot: 'libs/polyglot.min',
    search: 'search'
  },

  deps: ['search'],

  shim: {
	"jqueryui": {
	  exports:"$",
	  deps: ['jquery']
	},
    underscore: {
      exports: "_"
    },
    bootstrap: {
	    deps: ['jquery'],
        exports: 'Bootstrap'
    },
    backbone: {
      deps: ['underscore', 'jquery'],
      exports: 'Backbone'
    }
  }
});

/*
 * Load and init the GoatApp. which is added here as a ADM asynchronous module definition.
 */
require([
	'jquery',
	'jqueryvuln',
	'jqueryui',
	'underscore',
	'backbone',
	'bootstrap',
	'goatApp/goatApp'], function($,jqueryVuln,jqueryui,_,Backbone,Bootstrap,Goat){

    /*
     * The server rejects a state-changing request that does not carry the CSRF token, so every
     * request the application makes on the user's behalf has to present it. Spring writes the
     * token into the XSRF-TOKEN cookie; this reads it back out and attaches it as a header.
     *
     * It is installed once, globally, rather than at each call site: lesson forms are submitted
     * through jQuery by the lesson content view and Backbone's sync also goes through jQuery,
     * so a single prefilter covers all of them and no future call site can forget it. Safe
     * methods are skipped because Spring does not require a token for them, and cross-domain
     * requests are skipped so the token is never handed to a third party.
     */
    var readXsrfToken = function () {
        var match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/);
        if (match) {
            return decodeURIComponent(match[1]);
        }
        // The page also carries the token, which covers the case where the cookie has not been
        // issued yet for this session.
        var meta = document.querySelector('meta[name="_csrf"]');
        return meta ? meta.getAttribute('content') : null;
    };

    $.ajaxPrefilter(function (options, originalOptions, jqXHR) {
        if (options.crossDomain || /^(GET|HEAD|OPTIONS|TRACE)$/i.test(options.type || 'GET')) {
            return;
        }
        var token = readXsrfToken();
        if (token) {
            jqXHR.setRequestHeader('X-XSRF-TOKEN', token);
        }
    });

    Goat.initApp();
});
