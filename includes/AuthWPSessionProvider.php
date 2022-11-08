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

use MediaWiki\MediaWikiServices;
use MediaWiki\Session\ImmutableSessionProviderWithCookie;
use MediaWiki\Session\SessionInfo;
use MediaWiki\Session\UserInfo;
use MediaWiki\User\UserRigorOptions;


// Bootstrap WordPress using the relative path to its installation
// directory.  The default value, '..', implies that MediaWiki is
// installed in a directory next to WordPress's wp-load.php.
$WP_relpath = MediaWikiServices::getInstance()
            ->getConfigFactory()
            ->makeConfig( 'AuthWP' )
            ->get( 'AuthWPPath' );
require_once $WP_relpath . DIRECTORY_SEPARATOR . 'wp-load.php';


class AuthWPSessionProvider extends ImmutableSessionProviderWithCookie {
    public function __construct( $params = [] ) {
        parent::__construct( $params );

        $this->priority = MediaWikiServices::getInstance()
                        ->getConfigFactory()
                        ->makeConfig( 'AuthWP' )
                        ->get( 'AuthWPPriority' );
        if ( $this->priority < SessionInfo::MIN_PRIORITY ||
             $this->priority > SessionInfo::MAX_PRIORITY ) {
            throw new \InvalidArgumentException(
                __METHOD__ . ': ' . wfMessage( 'authwp-invalid-priority' ) );
        }
    }


    // Enable the "Log out" link.
    public function canChangeUser() {
        return true;
    }


    // Log out user from WordPress early, possibly before MediaWiki
    // logout completes.
    public static function onUserLogout( &$user ) {
        wp_logout();
        return true;
    }


    // If a WordPress session for the request exists, return a
    // SessionInfo object to identify the session, otherwise return
    // null.  This allows users already signed in to WordPress to be
    // automatically signed in to MediaWiki.
    public function provideSessionInfo( WebRequest $request ) {
        // Get the canonical name corresponding to the user logged in
        // to WordPress.  If there is no logged-in WordPress user, a
        // downstream session provider will have to provide the
        // session information instead.
        $wp_user = wp_get_current_user();
        if ( !$wp_user || !$wp_user->exists() ) {
            return null;
        }
        $wp_user_login = $this->userNameUtils->getCanonical(
            $wp_user->user_login, UserRigorOptions::RIGOR_USABLE );


        // Clear the UserID cookie if the corresponding username
        // matches the name of the logged-in WordPress user.  This
        // will prevent downstream session providers from validating
        // the sessions of users after they log out from WordPress.
        // Do not clear the UserName cookie, because it is used to
        // populate the "Username" field on MediaWiki's "Log in" page.
        $userID = $request->getCookie( 'UserID' );
        if ( $userID !== null ) {
            if ( UserInfo::newFromId( $userID )
                 ->getName() === $wp_user_login ) {
                $request->response()->clearCookie( 'UserID' );
            }
        }


        // From
        // https://www.mediawiki.org/wiki/Manual:SessionManager_and_AuthManager/SessionProvider_examples.
        $userInfo = UserInfo::newFromName( $wp_user_login, true );

        if ( $this->sessionCookieName === null ) {
            $id = $this->hashToSessionId( $wp_user_login );
            $persisted = false;
            $forceUse = true;
        } else {
            $id = $this->getSessionIdFromCookie( $request );
            $persisted = $id !== null;
            $forceUse = false;
        }

        return new SessionInfo( $this->priority, [
            'provider' => $this,
            'id' => $id,
            'userInfo' => $userInfo,
            'persisted' => $persisted,
            'forceUse' => $forceUse,
        ] );
    }
}
