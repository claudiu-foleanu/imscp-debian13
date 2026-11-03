/*
 * i-MSCP Web-based file manager - elFinder client initialization
 */
(function ($) {
    'use strict';

    $(function () {
        var $elfinder = $('#elfinder'), fm;

        if (!$elfinder.length) {
            return;
        }

        function getHeight() {
            return Math.max($(window).height() - $('#imscp-header').outerHeight(), 300);
        }

        // Session expired or logged out from another window
        $(document).ajaxComplete(function (event, xhr) {
            if (xhr && xhr.status === 401) {
                window.location.reload();
            }
        });

        fm = $elfinder.elfinder({
            url: $elfinder.data('connector'),
            baseUrl: $elfinder.data('base-url'),
            lang: $elfinder.data('lang') || 'en',
            cssAutoLoad: false,
            resizable: false,
            height: getHeight(),
            // Never send files to third-party services
            commandsOptions: {
                quicklook: {
                    googleDocsMimes: [],
                    officeOnlineMimes: [],
                    sharecadMimes: []
                },
                edit: {
                    extraOptions: {
                        creativeCloudApiKey: '',
                        managerUrl: ''
                    }
                }
            }
        }).elfinder('instance');

        $(window).on('resize', function () {
            if (fm) {
                fm.resize('100%', getHeight());
            }
        });
    });
})(jQuery);
