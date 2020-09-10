<?php

#use MediaWiki\MediaWikiServices;
#use MediaWiki\Session\ImmutableSessionProviderWithCookie;
#use MediaWiki\Session\UserInfo;
#use MediaWiki\Session\SessionInfo;
#use MediaWiki\Logger\LoggerFactory;
use MediaWiki\Auth\AbstractPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\PasswordAuthenticationRequest;
use MediaWiki\Auth\RememberMeAuthenticationRequest;
use MediaWiki\Auth\UserDataAuthenticationRequest;

#use MediaWiki\Auth\TemporaryPasswordAuthenticationRequest;
#use MediaWiki\Auth\PasswordDomainAuthenticationRequest;

use MediaWiki\MediaWikiServices;


#require_once( '../wp-load.php' );
$config = MediaWikiServices::getInstance()
        ->getConfigFactory()
        ->makeConfig( 'WPMW' );
require_once(
    $config->get( 'WPMWPath' ) . DIRECTORY_SEPARATOR . 'wp-load.php' );


class WPMWAuthenticationProvider extends
    AbstractPasswordPrimaryAuthenticationProvider {
    public function __construct() {
        parent::__construct();
        \Hooks::register( 'UserSetEmail', [ $this, 'onUserSetEmail' ]);
    }


    // Users must be created in WordPress, not here.  We do not
    // ACTUALLY create WordPress accounts here, even though we could!
    // Now we do, because the old AuthWP actually does.
    public function accountCreationType() {
        return self::TYPE_CREATE;
#        return self::TYPE_NONE;
    }


    // Must be implemented.
    public function beginPrimaryAccountCreation(
        $user, $creator, array $reqs ) {

        $this->logger->info( "MARKER in beginPrimaryAccountCreation()" );

        foreach ( $reqs as $req ) {
            $this->logger->info(
                "MARKER see request of type " . get_class($req) );
        }

        $req = AuthenticationRequest::getRequestByClass(
            $reqs, PasswordAuthenticationRequest::class );

        $this->logger->info(
            "MARKER in beginPrimaryAccountCreation(): user: " .
            $req->username );
        $this->logger->info(
            "MARKER in beginPrimaryAccountCreation(): password: " .
            $req->password );

        $userdata = AuthenticationRequest::getRequestByClass(
            $reqs, UserDataAuthenticationRequest::class );

        $this->logger->info(
            "MARKER in beginPrimaryAccountCreation(): email: " .
            $userdata->email );
        $this->logger->info(
            "MARKER in beginPrimaryAccountCreation(): realname: " .
            $userdata->realname );

        $wp_user = wp_insert_user( [
            'user_pass' => $req->password,
            'user_login' => $req->username,
            'user_email' => $userdata->email,
            'display_name' => $userdata->realname
        ] );
        if ( is_wp_error( $wp_user) ) {
            return $this->failResponse( $req );
        }

        return AuthenticationResponse::newPass();
    }


    // Come here with two requests: 1: PasswordAuthenticationRequest
    // and 2: RememberMeAuthenticationRequest.
    public function beginPrimaryAuthentication ( array $reqs ) {
        $this->logger->info(
            "MARKER in beginPrimaryAuthentication(): " . count( $reqs ) .
            " requests" );

        $req = AuthenticationRequest::getRequestByClass(
            $reqs, PasswordAuthenticationRequest::class );
        if ( $req && $req->username !== null && $req->password !== null ) {
            $this->logger->info(
                "MARKER in beginPrimaryAuthentication() with credentials" );

            if ( username_exists( $req->username ) ) {
                // The user is know to WordPress, so try to sign on.
                // Try to honor the setting of the "Remember me" box
                // from the supplied requests.
                $this->logger->info(
                    "MARKER in beginPrimaryAuthentication() in WordPress" );

                $creds = [
                    'user_login' => $req->username,
                    'user_password' => $req->password
                ];

                $req_rem = AuthenticationRequest::getRequestByClass(
                    $reqs, RememberMeAuthenticationRequest::class );
                $creds['remember'] = $req_rem && $req_rem->rememberMe;

                $wp_user = wp_signon( $creds, true );
                if ( $wp_user instanceof WP_User ) {
                    $this->logger->info(
                        "MARKER in beginPrimaryAuthentication() WordPress says yes" );
                    return AuthenticationResponse::newPass( $req->username );
                }

                $this->logger->info(
                    "MARKER in beginPrimaryAuthentication() WordPress says no" );
                return $this->failResponse( $req );
            } else {
                // From AuthManager's autoCreateUser() documentation:
                // "PrimaryAuthenticationProviders can invoke
                // [auto-creation] by returning a PASS from
                // beginPrimaryAuthentication/continuePrimaryAuthentication
                // with the username of a non-existing user."
                $this->logger->info(
                    "MARKER in beginPrimaryAuthentication() no WordPress: create" );
                return AuthenticationResponse::newPass( $req->username );
            }
        }

        // Let somebody else do the authentication.
        return AuthenticationResponse::newAbstain();
    }


/*
    // Not needed, identical to parent's implementation
    public function getAuthenticationRequests( $action, array $options ) {
        $this->logger->info("MARKER getAuthenticationRequests(): " . $action );

        switch ( $action ) {
        case AuthManager::ACTION_CHANGE:
        case AuthManager::ACTION_CREATE:
        case AuthManager::ACTION_LOGIN:
        case AuthManager::ACTION_REMOVE:
            return [ new PasswordAuthenticationRequest ];

        default:
            break;
        }

        return [];
    }
*/


    public function onUserSetEmail( $user, &$email ) {
        $wp_user = get_user_by( 'login', $user->getName() );
        if ( $wp_user ) {
            wp_update_user( [
                'ID' => $wp_user->ID,
                'user_email' => $email
            ] );
        }
    }


    // Allow the password to be changed.
    public function providerAllowsAuthenticationDataChange(
        AuthenticationRequest $req, $checkData = true ) {

        $this->logger->info(
            "MARKER in providerAllowsAuthenticationDataChange() request type " .
            get_class( $req ) . " checkData " . $checkData );
        return \StatusValue::newGood();
    }


    // Cannot change 'realname' to some arbitrary string, because that
    // would not map back to WordPress's 'display_name' cleanly.  In
    // WordPress, the display name is selected from a drop-down list.
    public function providerAllowsPropertyChange( $property ) {
        $this->logger->info(
            "MARKER providerAllowsPropertyChange(): " . $property );

        if ( $property === 'emailaddress' ) {
            return true;
        }
        return false;
    }


    public function providerChangeAuthenticationData(
        AuthenticationRequest $req ) {

        $this->logger->info(
            "MARKER in providerChangeAuthenticationData() with a " .
            get_class( $req ) );

        $wp_user = get_user_by( 'login', $req->username );
        if ( $wp_user ) {
            if ( $req->action === AuthManager::ACTION_CHANGE ) {
                // The corresponding credentials should result in a
                // successful login in the future.
                wp_update_user( [
                    'ID' => $wp_user->ID,
                    'user_pass' => $req->password
                ] );

            } else if ( $req->action === AuthManager::ACTION_REMOVE ) {
                // The corresponding credentials should no longer
                // result in a successful login.  XXX Lock the
                // account!  Could then do the same thing in the
                // implementation of providerRevokeAccessForUser();
                // currently no (standard) way to accomplish this
                // (several plugins exist)
            }
        }
    }


    // This must be implemented (no implementation in the abstract
    // class).
    public function testUserExists( $username, $flags = User::READ_NORMAL ) {
        $this->logger->info( "MARKER in testUserExists()" );
        return username_exists( $username ) ? true : false;
    }


    // Auto-creation requires the user to exist in WordPress.  This is
    // actually called.  Does this imply create the user in WordPress?
    // Note somewhere that users do not necessarily have the same ID
    // in WordPress as in MediaWiki.
    public function testUserForCreation(
        $user, $autocreate, array $options = [] ) {
        $this->logger->info("MARKER testUserForCreation()");

        if ( $autocreate ) {
            $wp_user = get_user_by( 'login', $user->getName() );
            if ( $wp_user ) {
                $user->setEmail( $wp_user->user_email );
                $user->setRealName( $wp_user->display_name );
                return \StatusValue::newGood();
            }

            // This is an internationalized string, defined in a
            // library somewhere?  XXX Fix it!
            return \StatusValue::newFatal( 'user-does-not-exist-in-WordPress' );
        }

        // testUserExists() will already prevent creating users that
        // exist in WordPress.
        return \StatusValue::newGood();
    }
}
