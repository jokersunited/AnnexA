/* Fundraising Grader
*
* Generic Copyright, yadda yadd yadda
*
* Plug-ins: jQuery Validate, jQuery
* Easing
*/

$(document).ready(function() {
    var current_fs, next_fs, previous_fs;
    var left, opacity, scale;
    var animating;

    var socket = io.connect();
    socket.on("message", data => {
    $("#loadtext").text(data.text);
    if (data.prog){
        $('.progress-bar').text(data.prog + "%")
        if (data.prog > 10){
            $('.progress-bar').css("width", data.prog + "%")
        }
    }

    });
    var navcheck = false;
    $(".view-collapse").click(function(){

        if(!navcheck){
            $(".dom-nav").css("display", "none");
            navcheck = true;
        }
        else {
            $(".dom-nav").css("display", "inline-block");
            navcheck = false;
        }

    });

    $(".next").click(function() {
        $(".page-form").css("display", "none")
        $("#loader").css("display", "block")
    });

    $(".recurl>a").click(function() {
        $(".page-form").css("display", "none")
        $("#loader").css("display", "block")
    });

    var modules = {
    $window: $(window),
    $html: $('html'),
    $body: $('body'),
    $container: $('.container'),
    init: function() {
        $(function() {
            modules.modals.init();
        });
    },
    modals: {
        trigger: $('.explanation'),
        modal: $('.modal'),
        scrollTopPosition: null,
        init: function() {
            var self = this;
            if (self.trigger.length > 0 && self.modal.length > 0) {
                modules.$body.append('<div class="modal-overlay"></div>');
                self.triggers();
            }
        },
        triggers: function() {
            var self = this;
            self.trigger.on('click', function(e) {
                e.preventDefault();
                var $trigger = $(this);
                self.openModal($trigger, $trigger.data('modalId'));
            });
            $('.modal-overlay').on('click', function(e) {
                e.preventDefault();
                self.closeModal();
            });
            modules.$body.on('keydown', function(e) {
                if (e.keyCode === 27) {
                    self.closeModal();
                }
            });
            $('.modal-close').on('click', function(e) {
                e.preventDefault();
                self.closeModal();
            });
        },
        openModal: function(_trigger, _modalId) {
            var self = this,
                scrollTopPosition = modules.$window.scrollTop(),
                $targetModal = $('#' + _modalId);
            self.scrollTopPosition = scrollTopPosition;
            modules.$html.addClass('modal-show').attr('data-modal-effect', $targetModal.data('modal-effect'));
            $targetModal.addClass('modal-show');
            modules.$container.scrollTop(scrollTopPosition);
        },
        closeModal: function() {
            var self = this;
            $('.modal-show').removeClass('modal-show');
            modules.$html.removeClass('modal-show').removeAttr('data-modal-effect');
            modules.$window.scrollTop(self.scrollTopPosition);
        }
    }
}
    modules.init();

});