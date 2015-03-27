use strict;
use warnings;

use Test::More;
plan tests => 13;

use vars qw($fd_status);
use POSIX qw(ttyname);
use Authen::PAM; # qw(:functions :constants);


sub pam_ok {
    my ($pamh, $pam_ret_val, $name) = @_ ;
    $name ||= '';
    local $Test::Builder::Level = $Test::Builder::Level + 1;
    my $T = Test::More->builder;
    $T->ok($pam_ret_val == PAM_SUCCESS(), "$name - $pam_ret_val - " . pam_strerror($pamh, $pam_ret_val));
}

sub my_fail_delay {
    $fd_status = shift;
    my $delay = shift;

    #diag("Status: $fd_status, Delay: $delay");
}

{
    my ($pamh, $item);
    my $pam_service = "login";
    my $login_name = getpwuid($<);
    my $tty_name = ttyname(fileno(STDIN)) or die "Can't obtain the tty name!\n";

    my $res;
    #$res = pam_start($pam_service, $login_name, \&Authen::PAM::pam_default_conv, $pamh);
    if ($login_name) {
        diag "The remaining tests will be run for service '$pam_service', user '$login_name', device '$tty_name'.";
        $res = pam_start($pam_service, $login_name, $pamh);
    } else { # If we cannot get the username then ask for it
        diag "The remaining tests will be run for service '$pam_service', device '$tty_name'.";
        $res = pam_start($pam_service, $pamh);
    }
    pam_ok($pamh, $res, 'pam_start');

    $res = pam_get_item($pamh, PAM_SERVICE(), $item);
    pam_ok($pamh, $res, 'pam_get_item PAM_SERVICE');
	is($item, $pam_service);

    #$res = pam_get_item($pamh, PAM_USER(), $item);
    #pam_ok($pamh, $res)
    #is($item, $login_name);

    #$res = pam_set_item($pamh, PAM_CONV(), \&Authen::PAM::pam_default_conv);
    #pam_ok($pamh, $res);

    $res = pam_get_item($pamh, PAM_CONV(), $item);
    pam_ok($pamh, $res, 'pam_get_item PAM_CONV');
	ok($item == \&Authen::PAM::pam_default_conv);

    $res = pam_set_item($pamh, PAM_TTY(), $tty_name);
    pam_ok($pamh, $res, 'PAM_TTY tty_name');

    $res = pam_get_item($pamh, PAM_TTY(), $item);
    pam_ok($pamh, $res, 'PAM_TTY item');
    is($item, $tty_name);

    SKIP: {
        skip 'environment functions are not supported by your PAM library', 2 if not HAVE_PAM_ENV_FUNCTIONS();
        $res = pam_putenv($pamh, "_ALPHA=alpha");
        pam_ok($pamh, $res, 'pam_putenv');

        my %en = pam_getenvlist($pamh);
        is($en{'_ALPHA'}, 'alpha', 'pam_getenvlist');
    };

    #if (HAVE_PAM_FAIL_DELAY()) {
    #    $res = pam_set_item($pamh, PAM_FAIL_DELAY(), \&my_fail_delay);
    #    pam_ok($pamh, $res);
    #} else {
    #    skip('custom fail delay function is not supported by your PAM library');
    #}

    SKIP: {
        skip 'prompting only without harness', 1 if $ENV{HARNESS_ACTIVE};
        if ($login_name) {
            diag "Now, you may be prompted to enter the password of '$login_name'.";
        } else{
            diag "Now, you may be prompted to enter a user name and a password.";
        }

        my $res = pam_authenticate($pamh, 0);
        #$res = pam_chauthtok($pamh);
        pam_ok($pamh, $res, 'pam_authenticate') or
            diag "The failure of test 9 could be due to your PAM configuration or typing an incorrect password.";
    };

    #if (HAVE_PAM_FAIL_DELAY()) {
    #    ok($res == $fd_status);
    #} else {
    #    skip('custom fail delay function is not supported by your PAM library');
    #}

    $res = pam_end($pamh, 0);
    ok($res == PAM_SUCCESS());

    diag('Checking the OO interface');
    $pamh = Authen::PAM->new($pam_service, $login_name);
    ok(ref($pamh));

    #$res = $pamh->pam_authenticate;
    #$res = $pamh->pam_chauthtok;
    #pam_ok($pamh, $res);

    $pamh = 0;  # this will destroy the object (and call pam_end)
}

