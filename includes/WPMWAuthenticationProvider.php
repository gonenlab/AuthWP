<?php
/**
 * WPMW session provider
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
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


// Bootstrap WordPress.  This seems rather foolish since surely the
// names of things are bound to clash somewhere, but we want to be
// able to handle everything as if WordPress was doing it natively
// including respecting any plugins that might be in place.
if ( php_sapi_name() !== 'cli' ) {
    // Relative path to WordPress installation.  In the default '..'
    // MediaWiki is installed in a 'wiki' directory off the main
    // WordPress root.
    $WP_relpath = MediaWikiServices::getInstance()
                 ->getConfigFactory()
                 ->makeConfig( 'WPMW' )
                 ->get( 'WPMWPath' );
    require_once $WP_relpath
        . DIRECTORY_SEPARATOR . 'wp-load.php';
    require_once $WP_relpath
        . DIRECTORY_SEPARATOR . 'wp-includes'
        . DIRECTORY_SEPARATOR . 'registration.php';
}


/**
 * A MediaWiki extension to delegate authentication and user
 * management to a local WordPress installation.  See
 * http://ciarang.com/wiki/page/WPMW for more information.
 */
class WPMWAuthenticationProvider extends
    AbstractPasswordPrimaryAuthenticationProvider {

    // Automatically create a local account when asked to log in a
    // user that does not exist locally.
    public function accountCreationType() {
        return self::TYPE_CREATE;
    }


    // Add a user created in MediaWiki to the WordPress database.  XXX
    // This will not result in an email notification from WordPress.
    public function beginPrimaryAccountCreation(
        $user, $creator, array $reqs ) {

        $req_password = AuthenticationRequest::getRequestByClass(
            $reqs, PasswordAuthenticationRequest::class );
        $req_userData = AuthenticationRequest::getRequestByClass(
            $reqs, UserDataAuthenticationRequest::class );

        if ( is_wp_error( wp_insert_user( [
            'display_name' => $req_userData->realname,
            'user_email' => $req_userData->email,
            'user_login' => $req_password->username,
            'user_pass' => $req_password->password
        ] ) ) ) {
            return $this->failResponse( $req_password );
        }

        return $this->beginPrimaryAuthentication( $reqs );
    }


    // Handle authentication, returning PASS if the given credentials
    // are good, FAIL if they are bad, or ABSTAIN if they cannot be
    // handled by this provider.
    public function beginPrimaryAuthentication ( array $reqs ) {
        $req_password = AuthenticationRequest::getRequestByClass(
            $reqs, PasswordAuthenticationRequest::class );
        if ( $req_password &&
             $req_password->username !== null &&
             $req_password->password !== null ) {

            if ( username_exists( $req_password->username ) ) {
                // The user is known to WordPress, so try to sign on.
                // Honor the "Remember me" setting from the supplied
                // requests.
                $creds = [
                    'user_login' => $req_password->username,
                    'user_password' => $req_password->password
                ];

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

            } else {
                $userInfo = UserInfo::newFromName( $req_password->username );
                if ( $userInfo->getId() !== 0) {
                    // User exists in MediaWiki, but not in WordPress:
                    // let downstream provider handle authentication.
                    return AuthenticationResponse::newAbstain();
                }
            }
        }

        // No password (the user must supply a username): invoke
        // auto-creation.
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


    // Set a new password for the given user.
    public function providerChangeAuthenticationData(
        AuthenticationRequest $req ) {

        $wp_user = get_user_by( 'login', $req->username );
        if ( $wp_user ) {
            if ( $req->action === AuthManager::ACTION_CHANGE ) {
                // The corresponding credentials should result in a
                // successful login in the future.
                wp_update_user( [
                    'ID' => $wp_user->ID,
                    'user_pass' => $req->password
                ] );
            }
        }
    }


    // See if the given user exists - true if so, false if not.
    public function testUserExists( $username, $flags = User::READ_NORMAL ) {
        return username_exists( $username );
    }


    public function testUserForCreation(
        $user, $autocreate, array $options = [] ) {

        if ( $autocreate ) {
            // MediaWiki auto-creation requires the user to exist in
            // WordPress.
            $wp_user = get_user_by( 'login', $user->getName() );
            if ( !$wp_user ) {
                return \StatusValue::newFatal(
                    "No corresponding WordPress user: cannot auto-create" );
            }

            $user->setEmail( $wp_user->user_email );
            $user->setRealName( $wp_user->display_name );
            return \StatusValue::newGood();
        }

        // If testUserExists() succeeds this should not be called.
        return \StatusValue::newGood();
    }
}
