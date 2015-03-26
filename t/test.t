use strict;

use Test::More;
plan tests => 10;

use vars qw($fd_status);
use POSIX qw(ttyname);
use Authen::PAM; # qw(:functions :constants);


sub pam_ok {
    my ($pamh, $pam_ret_val, $other_test) = @_ ;
    if ($pam_ret_val != PAM_SUCCESS()) {
        ok(0, "$pam_ret_val - " . pam_strerror($pamh, $pam_ret_val));
    }
    elsif (defined($other_test) && !$other_test) {
        ok(0);
    }
    else {
        ok(1);
    }
}

sub my_fail_delay {
    $fd_status = shift;
    my $delay = shift;

#  print "Status: $fd_status, Delay: $delay\n";
}

{
  my ($pamh, $item);
  my $res = -1;

  my $pam_service = "login";
  my $login_name = getpwuid($<);
  my $tty_name = ttyname(fileno(STDIN)) or
    die "Can't obtain the tty name!\n";

#  $res = pam_start($pam_service, $login_name, \&Authen::PAM::pam_default_conv, $pamh);
  if ($login_name) {
    print
      "---- The remaining tests will be run for service '$pam_service', ",
      "user '$login_name' and\n---- device '$tty_name'.\n";

    $res = pam_start($pam_service, $login_name, $pamh);
  } else { # If we cannot get the username then ask for it
    print
      "---- The remaining tests will be run for service '$pam_service' and\n",
      "---- device '$tty_name'.\n";

    $res = pam_start($pam_service, $pamh);
  }
  pam_ok($pamh, $res);

  $res = pam_get_item($pamh, PAM_SERVICE(), $item);
  pam_ok($pamh, $res, $item eq $pam_service);

#  $res = pam_get_item($pamh, PAM_USER(), $item);
#  pam_ok($pamh, $res, $item eq $login_name);

#  $res = pam_set_item($pamh, PAM_CONV(), \&Authen::PAM::pam_default_conv);
#  pam_ok($pamh, $res);

  $res = pam_get_item($pamh, PAM_CONV(), $item);
  pam_ok($pamh, $res, $item == \&Authen::PAM::pam_default_conv);

  $res = pam_set_item($pamh, PAM_TTY(), $tty_name);
  pam_ok($pamh, $res);

  $res = pam_get_item($pamh, PAM_TTY(), $item);
  pam_ok($pamh, $res, $item eq $tty_name);

  SKIP: {
    skip 'environment functions are not supported by your PAM library', 2 if not HAVE_PAM_ENV_FUNCTIONS();
    $res = pam_putenv($pamh, "_ALPHA=alpha");
    pam_ok($pamh, $res);

    my %en = pam_getenvlist($pamh);
    is($en{"_ALPHA"}, "alpha");
  };

#  if (HAVE_PAM_FAIL_DELAY()) {
#    $res = pam_set_item($pamh, PAM_FAIL_DELAY(), \&my_fail_delay);
#    pam_ok($pamh, $res);
#  } else {
#    skip('custom fail delay function is not supported by your PAM library');
#  }

   if ($login_name) {
     print
       "---- Now, you may be prompted to enter the password of '$login_name'.\n";
   } else{
     print
       "---- Now, you may be prompted to enter a user name and a password.\n";
   }

  $res = pam_authenticate($pamh, 0);
#  $res = pam_chauthtok($pamh);
  {
    pam_ok($pamh, $res);
    print 
      "---- The failure of test 9 could be due to your PAM configuration\n",
      "---- or typing an incorrect password.\n"
      if ($res != PAM_SUCCESS());
  }

#  if (HAVE_PAM_FAIL_DELAY()) {
#    ok($res == $fd_status);
#  } else {
#    skip('custom fail delay function is not supported by your PAM library');
#  }

  $res = pam_end($pamh, 0);
  ok($res == PAM_SUCCESS());

  # Checking the OO interface
  $pamh = new Authen::PAM($pam_service, $login_name);
  ok(ref($pamh));
#
#  $res = $pamh->pam_authenticate;
#  $res = $pamh->pam_chauthtok;
#  pam_ok($pamh, $res);
#
  $pamh = 0;  # this will destroy the object (and call pam_end)
}
