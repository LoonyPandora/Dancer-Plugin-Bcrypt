package Dancer::Plugin::Bcrypt;

use strict;

use Dancer::Plugin;
use Dancer::Config;

use Crypt::Eksblowfish::Bcrypt qw/en_base64/;
use Crypt::Random::Source;

our $VERSION = '0.0.1';

# See: http://codahale.com/how-to-safely-store-a-password/


register bcrypt => sub {
    my ($plaintext, $bcrypted) = @_;

    return if !$plaintext;

    # Sanity checks, and provide some good defaults.
    my $config = sanity_check();

    # On to the actual work...
    
    # If you pass a plaintext password and an bcrypted one (from a DB f.ex)
    # we hash the plaintext password using the same method, salt and
    # work factor as the stored version. If the plaintext password matches
    # the stored version then the resulting hashes should be identical.
    
    if ($bcrypted && $bcrypted =~ /^\$2a\$/) {
        return Crypt::Eksblowfish::Bcrypt::bcrypt($plaintext, $bcrypted);
    }

    # If we have been passed only the plaintext, then we
    # generate the bcrypted version with all new settings
    
    # Use bcrypt and append with a NULL - The accepted way to do it
    my $method = '$2a';

    # Has to be 2 digits exactly
    my $work_factor = sprintf("%02d", $config->{work_factor});

    # Salt must be exactly 16 octets, base64 encoded.
    my $salt = en_base64( generate_salt( $config->{random_factor} ) );

    # Create the settings string that we will use to bcrypt the plaintext
    # Read the docs of the Crypt:: modules for an explanation of this string
    my $new_settings = join('$', $method, $work_factor, $salt);


    return Crypt::Eksblowfish::Bcrypt::bcrypt($plaintext, $new_settings);
};


sub sanity_check {
    my $config = plugin_setting;

    # Takes ~0.007 seconds on 2011 hardware
    $config->{work_factor} ||= 4;

    # Uses /dev/urandom - which is pretty good
    $config->{random_factor} ||= 'weak';

    # Work factors higher than 31 aren't supported.
    if ($config->{work_factor} > 31) {
        $config->{work_factor} = 31;
    };

    # Can only specify weak or strong as random_factor
    unless ( $config->{random_factor} ~~ ['strong', 'weak'] ) {
        $config->{random_factor} = 'weak';
    }

    return {
        work_factor   => $config->{work_factor},
        random_factor => $config->{random_factor},
    };
}


sub generate_salt {
    my ($type) = @_;

    if ($type eq 'strong') {
        return Crypt::Random::Source::get_strong(16);
    }

    return Crypt::Random::Source::get_weak(16);
}



register_plugin;

1;
