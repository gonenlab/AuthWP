<?php
/**
 * Copyright 2020 Howard Hughes Medical Institute
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

use MediaWiki\Auth\AbstractPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\PasswordAuthenticationRequest;
use MediaWiki\Auth\RememberMeAuthenticationRequest;
use MediaWiki\Auth\UserDataAuthenticationRequest;
use MediaWiki\MediaWikiServices;
use MediaWiki\Session\UserInfo;


// Bootstrap WordPress using the relative path to its installation
// directory.  The default value, '..', implies that MediaWiki is
// installed in a directory next to WordPress's wp-load.php.
$WP_relpath = MediaWikiServices::getInstance()
            ->getConfigFactory()
            ->makeConfig( 'AuthWP' )
            ->get( 'AuthWPPath' );
require_once $WP_relpath . DIRECTORY_SEPARATOR . 'wp-load.php';


class AuthWPAuthenticationProvider extends
    AbstractPasswordPrimaryAuthenticationProvider {

    // Automatically create an account when asked to log in a
    // WordPress user that does not exist in MediaWiki.
    public function accountCreationType() {
        return self::TYPE_CREATE;
    }


    // Add a user created in MediaWiki to WordPress and send an email
    // notification.
    public function beginPrimaryAccountCreation(
        $user, $creator, array $reqs ) {

        $req_password = AuthenticationRequest::getRequestByClass(
            $reqs, PasswordAuthenticationRequest::class );
        $req_userData = AuthenticationRequest::getRequestByClass(
            $reqs, UserDataAuthenticationRequest::class );

        $user_id = wp_insert_user( [
            'display_name' => $req_userData->realname,
            'user_email' => $req_userData->email,
            'user_login' => $req_password->username,
            'user_pass' => $req_password->password
        ] );
        if ( is_wp_error( $user_id ) ) {
            return $this->failResponse( $req_password );
        }

        $notify = Sanitizer::validateEmail(
            $req_userData->email ) ? 'both' : 'admin';
        wp_send_new_user_notifications( $user_id, $notify );

        return $this->beginPrimaryAuthentication( $reqs );
    }


    // Handle authentication: return PASS if the given credentials are
    // good, FAIL if they are bad, or ABSTAIN if they cannot be
    // handled by this provider.
    public function beginPrimaryAuthentication ( array $reqs ) {
        $req_password = AuthenticationRequest::getRequestByClass(
            $reqs, PasswordAuthenticationRequest::class );
        if ( $req_password &&
             $req_password->username !== null &&
             $req_password->password !== null ) {

            if ( username_exists( $req_password->username ) ) {
                // The user is known to WordPress, so try to sign on.
                $creds = [
                    'user_login' => $req_password->username,
                    'user_password' => $req_password->password
                ];

                // Honor the "Remember me" setting from the supplied
                // requests.
                $req_rememberMe = AuthenticationRequest::getRequestByClass(
                    $reqs, RememberMeAuthenticationRequest::class );
                if ( $req_rememberMe ) {
                    $creds[ 'remember' ] = $req_rememberMe->rememberMe;
                }

                if ( is_wp_error( wp_signon( $creds, true ) ) ) {
                    return $this->failResponse( $req_password );
                }
                return AuthenticationResponse::newPass(
                    $req_password->username );

            } elseif ( UserInfo::newFromName( $req_password->username )
                       ->getId() !== 0) {
                // The user exists in MediaWiki, but not in WordPress:
                // let a downstream provider handle authentication.
                return AuthenticationResponse::newAbstain();
            }
        }

        // No password (but the user must have supplied a username):
        // invoke auto-creation.
        return AuthenticationResponse::newPass(
            $req_password->username );
    }


    // Allow the password to be changed.
    public function providerAllowsAuthenticationDataChange(
        AuthenticationRequest $req, $checkData = true ) {

        if ( $req->action === AuthManager::ACTION_REMOVE ) {
            // The corresponding credentials should no longer result
            // in a successful login, but that cannot be implemented
            // here because there does not appear to be reliable way
            // to disable an account in WordPress.
            return \StatusValue::newGood( 'ignored' );
        }
        return \StatusValue::newGood();
    }


    public function providerAllowsPropertyChange( $property ) {
        return false;
    }


    // Set a new password for the user.  The corresponding credentials
    // should result in a successful login in the future.
    public function providerChangeAuthenticationData(
        AuthenticationRequest $req ) {

        $wp_user = get_user_by( 'login', $req->username );
        if ( $wp_user ) {
            if ( $req->action === AuthManager::ACTION_CHANGE ) {
                wp_update_user( [
                    'ID' => $wp_user->ID,
                    'user_pass' => $req->password
                ] );
            }
        }
    }


    public function testUserExists( $username, $flags = User::READ_NORMAL ) {
        return username_exists( $username );
    }


    // MediaWiki auto-creation requires the user to exist in
    // WordPress.  If testUserExists() returns true this should not be
    // called.
    public function testUserForCreation(
        $user, $autocreate, array $options = [] ) {

        if ( $autocreate ) {
            $wp_user = get_user_by( 'login', $user->getName() );
            if ( !$wp_user ) {
                return \StatusValue::newFatal(
                    wfMessage( 'authwp-no-wordpress-user' ) );
            }

            $user->setEmail( $wp_user->user_email );
            $user->setRealName( $wp_user->display_name );
        }

        return \StatusValue::newGood();
    }
}
