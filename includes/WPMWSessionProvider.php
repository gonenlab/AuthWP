<?php
/**
 * WPMW session provider
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use MediaWiki\MediaWikiServices;
use MediaWiki\Session\ImmutableSessionProviderWithCookie;
use MediaWiki\Session\SessionInfo;
use MediaWiki\Session\UserInfo;


if ( !defined( 'MEDIAWIKI' ) ) {
    die( "Not an entry point." );
}


// Bootstrap Wordpress. This seems rather foolish since surely the
// names of things are bound to clash somewhere, but we want to be
// able to handle everything as if Wordpress was doing it natively
// including respecting any plugins that might be in place.
if ( php_sapi_name() !== 'cli' ) {
    // Relative path to Wordpress installation. In the default '..' we
    // have MediaWiki installed in a 'wiki' directory off the main
    // Wordpress root.
    $WP_relpath = MediaWikiServices::getInstance()
                 ->getConfigFactory()
                 ->makeConfig( 'WPMW' )
                 ->get( 'WPMWRelPath' );
    require_once($WP_relpath .
                 DIRECTORY_SEPARATOR . 'wp-load.php' );
    require_once($WP_relpath .
                 DIRECTORY_SEPARATOR . 'wp-includes' .
                 DIRECTORY_SEPARATOR . 'registration.php');
}


// Wordpress has escaped all these in wp-settings.php - we need to
// unescape them again if they weren't meant to be escaped.
if(php_sapi_name() != 'cli' && !get_magic_quotes_gpc()) {
    $_GET    = stripslashes_deep($_GET   );
    $_POST   = stripslashes_deep($_POST  );
    $_COOKIE = stripslashes_deep($_COOKIE);
}


/**
 * MediaWiki extension to delegate authentication and user management
 * to a local Wordpress installation.
 * See http://ciarang.com/wiki/page/WPMW for more information.
 * Version 0.3.1
 * Copyright (C) 2008-13 Ciaran Gultnieks <ciaran@ciarang.com>
 *
 * We'll derive our class from MediaWiki's
 * ImmutableSessionProviderWithCookie class...
 */
class WPMWSessionProvider extends ImmutableSessionProviderWithCookie {

    // Constructor
    public function __construct( $params = [] ) {
        parent::__construct( $params );

        $this->priority = MediaWikiServices::getInstance()
                        ->getConfigFactory()
                        ->makeConfig( 'WPMW' )
                        ->get( 'WPMWPriority' );
        if ( $this->priority < SessionInfo::MIN_PRIORITY ||
             $this->priority > SessionInfo::MAX_PRIORITY ) {
            throw new \InvalidArgumentException(
                __METHOD__ . ": Invalid priority" );
        }
    }


    // Enable the "Log out" link.
    public function canChangeUser() {
        return true;
    }


    // Handler for the MediaWiki UserLogout hook.
    //
    // Log out user from WordPress early, possibly before MediaWiki
    // completes logout.
    public static function onUserLogout( &$user ) {
        // Log out of Wordpress as well...
        wp_logout();
        return true;
    }


    // Allows users
    // already signed in to Wordpress to be automatically signed in to
    // MediaWiki.
    //
    // If a WordPress session for the request exists, return a
    // SessionInfo object to identify the session, otherwise return
    // null.
    public function provideSessionInfo( WebRequest $request ) {

        // Is there a Wordpress user with a valid session?
        $wp_user = wp_get_current_user();
        if ( !$wp_user->exists() ) {
            return null;
        }
        $wp_user_login =  User::getCanonicalName(
            $wp_user->user_login, 'usable' );


        // Just return true meaning that logins can only be authenticated in
        // this module, and not checked against the mediawiki db...
        //
        // Clear the UserID cookie if the corresponding username
        // matches the name of the user logged in through WordPress.
        // This will prevent downstream session providers from
        // validating the session after the user logs out from
        // WordPress.  Do not clear the UserName cookie, because it is
        // used to populate the "Username" field on MediaWiki's "Log
        // in" page.
        $userID = $request->getCookie( 'UserID' );
        if ( $userID !== null ) {
            $userInfo = UserInfo::newFromId( $userID );
            if ( $userInfo && $userInfo->getName() === $wp_user_login ) {
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
