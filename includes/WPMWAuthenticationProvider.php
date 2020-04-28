<?php

# XXX Probably a bunch of stuff here that is not used.
use MediaWiki\MediaWikiServices;
use MediaWiki\Session\ImmutableSessionProviderWithCookie;
use MediaWiki\Session\UserInfo;
use MediaWiki\Session\SessionInfo;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\Auth\AbstractPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\PasswordAuthenticationRequest;
use MediaWiki\Auth\RememberMeAuthenticationRequest;

use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\TemporaryPasswordAuthenticationRequest;
use MediaWiki\Auth\PasswordDomainAuthenticationRequest;

# Needed if the Session stuff is disabled.
require_once("../wp-load.php"); // XXX Placement? require() or require_once()?


class WPMWAuthenticationProvider
    extends AbstractPasswordPrimaryAuthenticationProvider
{
/*
    public function __construct( $params = [] ) {
        parent::__construct( $params );
    }

    public function setConfig( \Config $config ) {
        parent::setConfig( $config );
    }

    protected function getPasswordResetData( $username, $data ) {
        return false;
    }

    // This is implanted just to disable password changes.
    public function providerAllowsAuthenticationDataChange(
        MediaWiki\Auth\AuthenticationRequest $req, $checkData = true
    ) {
        $rest = \StatusValue::newGood();
        $rest->setOK(false);
        return $rest;
    }

    // This one disables any other properties we need to block
    public function providerAllowsPropertyChange( $property )
    {
        if (in_array($property, array(
            'emailaddress'
        )))
            return false;
        return true;
    }
*/


    public function beginPrimaryAuthentication ( array $reqs ) {
        // Get here with two requests: 1:
        // PasswordAuthenticationRequest and 2:
        // RememberMeAuthenticationRequest; ignore the latter for now.

        $this->logger->info( "MARKER in beginPrimaryAuthentication()" );
#        return

        // Build the creds array and initialize it with the 'remember'
        // member.  XXX Move this bit into the other conditional?
        $req = AuthenticationRequest::getRequestByClass(
            $reqs, RememberMeAuthenticationRequest::class );
        $creds = array( 'remember' => $req && $req->rememberMe );


        // Sign the user on to WordPress.  Note that the user need not
        // exist in MediaWiki for getCanonicalName() to succeed.  XXX
        // Check authorization here, or is that better done in
        // session?
        $req = AuthenticationRequest::getRequestByClass(
            $reqs, PasswordAuthenticationRequest::class );
        if ( $req && $req->username !== null && $req->password !== null ) {

            $this->logger->info(
                "MARKER in beginPrimaryAuthentication() have credentials" );

            if ( !username_exists($req->username) ) {
                // If the user is not know, let somebody else do the
                // authentication.
                $this->logger->info(
                    "MARKER in beginPrimaryAuthentication() not in WordPress" );
                return AuthenticationResponse::newAbstain();
            }

            $creds['user_login'] = $req->username;
            $creds['user_password'] = $req->password;
            $user = wp_signon( $creds, true );

            // Only do this if actually permitted, otherwise the
            // username/password will be verified against the next
            // session provider and succeed: XXX fix this by making
            // our session provider final?
            if ( $user instanceof WP_User ) {
                $this->logger->info(
                    "MARKER in beginPrimaryAuthentication() WordPress says yes" );

                // wp_set_current_user( $user->ID ); # XXX Not needed after all?
                $username = User::getCanonicalName(
                    $user->user_login, 'usable' );
                if ( $username ) {
                    return AuthenticationResponse::newPass( $username );
                }
            }

#            return parent::beginPrimaryAuthentication( $reqs );

            $this->logger->info(
                "MARKER in beginPrimaryAuthentication() WordPress says no" );
            return $this->failResponse( $req );
        }


#        foreach ( $reqs as $t ) {
#            $this->logger->info( "MARKER: see request " . get_class($t) );
#        }

        return AuthenticationResponse::newAbstain();
    }


    public function testUserExists( $username, $flags = User::READ_NORMAL ) {
        $username = User::getCanonicalName( $username, 'usable' );

        $this->logger->info( "MARKER in testUserExists()" );

        if ( $username && username_exists( $username )) {
            return true;
        }
        return false;
    }


    public function providerAllowsAuthenticationDataChange(
        AuthenticationRequest $req, $checkData = true ) {

        // Why do we even get here?!
        return \StatusValue::newGood( 'ignored' );


        $this->logger->info(
            "MARKER in providerAllowsAuthenticationDataChange() request type " .
            get_class($req) . " checkData " . $checkData);
#        return \StatusValue::newGood( 'ignored' );

        if ( $req instanceof PasswordAuthenticationRequest) {
            $this->logger->info("MARKER: PasswordAuthenticationRequest");

            return \StatusValue::newGood( 'ignored' );
        } else if ( $req instanceof TemporaryPasswordAuthenticationRequest ) {
            $this->logger->info(
                "MARKER: TemporaryPasswordAuthenticationRequest");
            return \StatusValue::newGood( 'ignored' ); # XXX

        } else {
            $this->logger->info("MARKER: Some other authentication request");
        }


        // XXX Could actually allow passwords to be changed.  This is
        // an internationalized string?
        return \StatusValue::newGood( 'ignored' );

        return \StatusValue::newFatal(
            'authmanager-authplugin-setpass-denied' );
    }


    // XXX This should not be called, then?
    public function providerChangeAuthenticationData(
        AuthenticationRequest $req ) {
        $this->logger->info( "MARKER in providerChangeAuthenticationData()" );
    }


    // Users must be created in WordPress, not here.  XXX But we
    // should provision users FROM WordPress here, somehow.
    public function accountCreationType() {
        $this->logger->info( "MARKER in accountCreationType()" );
        return self::TYPE_NONE;
    }


    // Shouldn't call this when accountCreationType() is NONE
    public function beginPrimaryAccountCreation(
        $user, $creator, array $reqs ) {
        $this->logger->info( "MARKER in beginPrimaryAccountCreation()" );

        return AuthenticationResponse::newAbstain();
    }


    // XXX ALL BELOW added for testing purposes
    public function getAuthenticationRequests( $action, array $options ) {

        // Exactly one should have AuthenticationRequest::$required
        // set to REQUIRED

        switch ( $action ) {
        case AuthManager::ACTION_LOGIN:
            $this->logger->info(
                "MARKER getAuthenticationRequests(): ACTION_LOGIN " .
                count($options) . " options");

            foreach ($options as $option) {
                $this->logger->info(
                    "MARKER see option " . $option .
                    " type " . gettype($option) );
            }

#                return [];

            return [ new PasswordAuthenticationRequest ];
            break;

        case AuthManager::ACTION_CREATE:
            $this->logger->info(
                "MARKER getAuthenticationRequests(): ACTION_CREATE");
            break;

        case AuthManager::ACTION_CHANGE:
            $this->logger->info(
                "MARKER getAuthenticationRequests(): ACTION_CHANGE");

#                return [ new PasswordAuthenticationRequest ];

            return [];
            break;

        case AuthManager::ACTION_REMOVE:
            $this->logger->info(
                "MARKER getAuthenticationRequests(): ACTION_REMOVE");
            break;

        default:
            $this->logger->info("MARKER getAuthenticationRequests(): default");
            break;
        }

        return [];
    }


    public function testUserCanAuthenticate( $username ) {
        $this->logger->info( "MARKER testUserCanAuthenticate()" );
        return true;
    }


    public function providerAllowsPropertyChange( $property ) {
        $this->logger->info( "MARKER providerAllowsPropertyChange()" );
    }


    public function providerRevokeAccessForUser( $username ) {
        $this->logger->info( "MARKER providerRevokeAccessForUser()" );
    }
}
