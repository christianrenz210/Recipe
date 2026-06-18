var API = (location.hostname === '127.0.0.1' || location.hostname === 'localhost') && location.port !== '3000' ? 'http://localhost:3000' : '';
$.ajaxSetup({ xhrFields: { withCredentials: true } });

$(document).ready(function () {

    // ===== ACTIVE NAV LINK =====
    var path = window.location.pathname;
    var page = path.split("/").pop();
    $('.navbar .nav-link').each(function () {
        var href = $(this).attr('href');
        if (href === page || (page === '' && href === 'index.html')) {
            $(this).addClass('active');
        }
    });

    // ===== SMOOTH SCROLL =====
    $('a[href*="#"]').not('[href="#"]').click(function (e) {
        if (location.pathname.replace(/^\//, '') === this.pathname.replace(/^\//, '') &&
            location.hostname === this.hostname) {
            var target = $(this.hash);
            target = target.length ? target : $('[name=' + this.hash.slice(1) + ']');
            if (target.length) {
                e.preventDefault();
                $('html, body').animate({
                    scrollTop: target.offset().top - 80
                }, 600);
            }
        }
    });

    // ===== RECIPE FILTERING =====
    $('.filter-btn').click(function () {
        $('.filter-btn').removeClass('active');
        $(this).addClass('active');
        var filter = $(this).data('filter');
        if (filter === 'all') {
            $('.recipe-card').parent().show();
        } else {
            $('.recipe-card').parent().hide();
            $('.recipe-card[data-category="' + filter + '"]').parent().show();
        }
    });

    // ===== SEARCH FILTER =====
    $('#recipeSearch').on('keyup', function () {
        var value = $(this).val().toLowerCase();
        $('.recipe-card').filter(function () {
            $(this).parent().toggle($(this).find('h5').text().toLowerCase().indexOf(value) > -1);
        });
    });

    // ===== PASSWORD STRENGTH =====
    $('#regPassword').on('keyup', function () {
        var val = $(this).val();
        var strength = 0;
        var bar = $('.password-strength .bar');
        if (val.length >= 6) strength += 25;
        if (val.match(/[a-z]+/)) strength += 25;
        if (val.match(/[A-Z]+/)) strength += 25;
        if (val.match(/[0-9]+/) || val.match(/[$@#&!]+/)) strength += 25;

        bar.css('width', strength + '%');
        if (strength <= 25) {
            bar.css('background', '#e74c3c');
        } else if (strength <= 50) {
            bar.css('background', '#f39c12');
        } else if (strength <= 75) {
            bar.css('background', '#3498db');
        } else {
            bar.css('background', '#00b894');
        }
    });

    // ===== PASSWORD MATCH =====
    $('#regConfirmPassword').on('keyup', function () {
        var pass = $('#regPassword').val();
        var confirm = $(this).val();
        if (confirm.length > 0) {
            if (pass === confirm) {
                $(this).removeClass('is-invalid').addClass('is-valid');
            } else {
                $(this).removeClass('is-valid').addClass('is-invalid');
            }
        } else {
            $(this).removeClass('is-valid is-invalid');
        }
    });

    // ===== LOGIN FORM VALIDATION =====
    $('#loginForm').submit(function (e) {
        e.preventDefault();
        var valid = true;
        var email = $('#loginEmail').val().trim();
        var password = $('#loginPassword').val();

        if (email === '') {
            $('#loginEmail').addClass('is-invalid');
            valid = false;
        } else {
            $('#loginEmail').removeClass('is-invalid');
        }
        if (password === '') {
            $('#loginPassword').addClass('is-invalid');
            valid = false;
        } else {
            $('#loginPassword').removeClass('is-invalid');
        }

        if (valid) {
            $('#loginBtn').html('<span class="spinner-border spinner-border-sm me-2"></span>Signing In...').prop('disabled', true);
            $.post(API + '/api/login', { email: email, password: password })
                .done(function (user) {
                    if (user.role === 'admin') {
                        window.location.href = '/admin/dashboard.html';
                    } else {
                        window.location.href = '/user/dashboard.html';
                    }
                })
                .fail(function (xhr) {
                    var err = xhr.responseJSON ? xhr.responseJSON.error : 'Login failed';
                    $('#loginBtn').html('Sign In <i class="fas fa-arrow-right ms-2"></i>').prop('disabled', false);
                    $('.invalid-feedback').text(err).show();
                });
        }
    });

    // ===== REGISTER FORM VALIDATION =====
    $('#registerForm').submit(function (e) {
        e.preventDefault();
        var valid = true;
        var name = $('#regName').val().trim();
        var email = $('#regEmail').val().trim();
        var password = $('#regPassword').val();
        var confirm = $('#regConfirmPassword').val();
        var terms = $('#termsCheck').is(':checked');

        if (name === '') { $('#regName').addClass('is-invalid'); valid = false; }
        else { $('#regName').removeClass('is-invalid'); }

        if (email === '') { $('#regEmail').addClass('is-invalid'); valid = false; }
        else { $('#regEmail').removeClass('is-invalid'); }

        if (password === '' || password.length < 6) { $('#regPassword').addClass('is-invalid'); valid = false; }
        else { $('#regPassword').removeClass('is-invalid'); }

        if (confirm === '' || confirm !== password) { $('#regConfirmPassword').addClass('is-invalid'); valid = false; }
        else { $('#regConfirmPassword').removeClass('is-invalid'); }

        if (!terms) { $('.terms-error').show(); valid = false; }
        else { $('.terms-error').hide(); }

        if (valid) {
            $('#registerBtn').html('<span class="spinner-border spinner-border-sm me-2"></span>Creating Account...').prop('disabled', true);
            $.post(API + '/api/register', { name: name, email: email, password: password })
                .done(function () {
                    window.location.href = '/user/dashboard.html';
                })
                .fail(function (xhr) {
                    var err = xhr.responseJSON ? xhr.responseJSON.error : 'Registration failed';
                    $('#registerBtn').html('Create Account <i class="fas fa-arrow-right ms-2"></i>').prop('disabled', false);
                    $('.invalid-feedback').text(err).show();
                });
        }
    });

    // ===== CONTACT FORM =====
    $('#contactForm').submit(function (e) {
        e.preventDefault();
        var valid = true;
        $(this).find('.form-control').each(function () {
            if ($(this).val().trim() === '') {
                $(this).addClass('is-invalid');
                valid = false;
            } else {
                $(this).removeClass('is-invalid');
            }
        });
        if (valid) {
            $('#contactBtn').html('<span class="spinner-border spinner-border-sm me-2"></span>Sending...').prop('disabled', true);
            setTimeout(function () {
                $('#contactBtn').html('<i class="fas fa-check me-2"></i>Sent!').prop('disabled', false);
                $('#contactForm')[0].reset();
                setTimeout(function () {
                    $('#contactBtn').html('Send Message <i class="fas fa-paper-plane ms-2"></i>');
                }, 2000);
            }, 1500);
        }
    });

    // ===== NEWSLETTER =====
    $('#newsletterForm').submit(function (e) {
        e.preventDefault();
        var email = $('#newsletterEmail').val().trim();
        if (email !== '') {
            $(this).find('button').html('Subscribed! <i class="fas fa-check ms-2"></i>');
            setTimeout(function () {
                $('#newsletterEmail').val('');
                $('#newsletterForm button').html('Subscribe <i class="fas fa-paper-plane ms-2"></i>');
            }, 2000);
        }
    });

    // ===== ADMIN SIDEBAR TOGGLE =====
    $('.sidebar-toggle').click(function () {
        $('.sidebar').toggleClass('show');
    });

    // ===== CLOSE SIDEBAR ON OUTSIDE CLICK (ADMIN) =====
    $(document).click(function (e) {
        if ($(window).width() <= 991) {
            if (!$(e.target).closest('.sidebar').length && !$(e.target).closest('.sidebar-toggle').length) {
                $('.sidebar').removeClass('show');
            }
        }
    });

    // ===== COUNTER ANIMATION =====
    function animateCounter(el) {
        var target = parseInt($(el).data('target'));
        if (!target) { $(el).text(0); return; }
        var speed = 50;
        var current = 0;
        var increment = Math.ceil(target / speed);
        var timer = setInterval(function () {
            current += increment;
            if (current >= target) {
                $(el).text(target);
                clearInterval(timer);
            } else {
                $(el).text(current);
            }
        }, 30);
    }

    $.get(API + '/api/stats').done(function (stats) {
        $('.counter[data-stat="recipes"]').data('target', stats.recipes);
        $('.counter[data-stat="users"]').data('target', stats.users);
        $('.counter[data-stat="chefs"]').data('target', stats.chefs);
    }).always(function () {
        $('.counter').each(function () {
            animateCounter(this);
        });
    });

    // ===== BACK TO TOP =====
    var backToTop = $('<button id="backToTop" class="btn btn-primary-custom" style="position:fixed;bottom:30px;right:30px;display:none;z-index:999;width:45px;height:45px;padding:0;border-radius:50%;"><i class="fas fa-arrow-up"></i></button>');
    $('body').append(backToTop);

    $(window).scroll(function () {
        if ($(this).scrollTop() > 300) {
            $('#backToTop').fadeIn();
        } else {
            $('#backToTop').fadeOut();
        }
    });

    $('#backToTop').click(function () {
        $('html, body').animate({ scrollTop: 0 }, 500);
    });

});
