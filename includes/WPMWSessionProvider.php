<?php
/**
 * WPMWSessionProvider.php
 * MediaWiki extension to delegate authentication and user management
 * to a local Wordpress installation.
 * See http://ciarang.com/wiki/page/WPMW for more information.
 * Version 0.3.1
 * Copyright (C) 2008-13 Ciaran Gultnieks <ciaran@ciarang.com>
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
 *
 * From https://www.mediawiki.org/wiki/Manual:SessionManager_and_AuthManager/SessionProvider_examples
 */

use MediaWiki\Session\SessionProvider;
use MediaWiki\Session\CookieSessionProvider;
#use MediaWiki\Session\ImmutableSessionProviderWithCookie;
use MediaWiki\Session\SessionInfo;
use MediaWiki\Session\UserInfo;
use MediaWiki\Session\SessionManager;

#use MediaWiki\WebRequest;

require_once("../wp-load.php"); // XXX Placement? require() or require_once()?


// XXX What about inheriting from CookieSessionProvider instead, like
// Auth_RemoteUser?  That restores the logout button, but it seems we
// never get to the AuthProvider!  What should provideSessionInfo()
// return in that case?  Something new and the AuthProvider has to
// fill in the details?
class WPMWSessionProvider extends CookieSessionProvider {
#class WPMWSessionProvider extends ImmutableSessionProviderWithCookie {

    public function __construct( $params = [] ) {

        $params += [ 'priority' => SessionInfo::MAX_PRIORITY ];

        parent::__construct( $params );
    }


    public function provideSessionInfo( WebRequest $request ) {

        $this->logger->info( "MARKER: Here we go" );


        // Returns null when nobody logged in.
        $sessionInfo = parent::provideSessionInfo( $request );

        if ( $sessionInfo === null ) {
            $this->logger->info( "MARKER: sessionInfo is null" );

            $user = wp_get_current_user();
            if ( $user->exists() ) {

                $this->logger->info("MARKER: have WP user with authorization");

                // userInfo is guaranteed to match the logged in WP
                // user, no need to check whether
                // $userInfo()->getName() matches $user->user_login.
                try {
                    $userInfo = UserInfo::newFromName(
                        $user->user_login, true );
                } catch ( \InvalidArgumentException $ex ) {
                    // XXX Expect to get here for authenticated users
                    // that have not been provisioned.  Either users
                    // are provisioned by AuthProvider, or they should
                    // be provisioned here?
                    return null;
                }

                $this->logger->info("MARKER: WP user is provisioned");

                // This is NULL
                $sessionId = $this->getCookie(
                    $request, $this->params['sessionName'], '' );
                $sessionId = $this->hashToSessionId( $user->user_login );
                $this->logger->info(
                    "MARKER: have sessionId type " . gettype($sessionId) .
                    " with value " . $sessionId );
                $this->logger->info(
                    "MARKER sessionId valid?" .
                    SessionManager::validateSessionid( $sessionId) );

                // XXX Should sett forceHTTPS
                return new SessionInfo( $this->priority, [
                    'provider' => $this,
                    'id' => $sessionId,
                    'userInfo' => $userInfo, // XXX what about $userInfo->verified()
                    'persisted' => true, // XXX was false, or rather $persisted,
#                    'forceUse' => $forceUse, // XXX was true, or rather $forceUse
            ] );


            }

        } else {
            $this->logger->info(
                "MARKER: forceHTTPS(): " .
                $sessionInfo->forceHTTPS() );
            $this->logger->info(
                "MARKER: forceUse(): " .
                $sessionInfo->forceUse() );
            $this->logger->info(
                "MARKER: getId(): " .
                $sessionInfo->getId() );
            $this->logger->info(
                "MARKER: getPriority(): " .
                $sessionInfo->getPriority() );
            $this->logger->info(
                "MARKER: getProvider(): " .
                $sessionInfo->getProvider() );
            $this->logger->info(
                "MARKER: getProviderMetadata(): " .
                $sessionInfo->getProviderMetadata() );
            $this->logger->info(
                "MARKER: getUserInfo(): " .
                $sessionInfo->getUserInfo() );
            $this->logger->info(
                "MARKER: isIdSafe(): " .
                $sessionInfo->isIdSafe() );
            $this->logger->info(
                "MARKER: wasPersisted(): " .
                $sessionInfo->wasPersisted() );
            $this->logger->info(
                "MARKER: wasRemembered(): " .
                $sessionInfo->wasRemembered() );

            $this->logger->info( "MARKER: end of stuff" );
        }

        // OK, this works... except if user logs out of WP, then this
        // is still around.
        $user = wp_get_current_user();
        if ( !$user->exists() ) {
            $this->logger->info("MARKER: Session OK, but WP user logged out" );
            $this->unpersistSession( $request ); // Does not work
        }

        return $sessionInfo;

        $user = wp_get_current_user();
        if ( !$user->exists() ) {
            // If we have a MediaWiki cookie/session here delete it!
            // No longer logged in to WordPress!  Otherwise downstream
            // SessionProviders will allow work to continue.  Log in
            // on MediaWiki, log out in WordPress, return to MediaWiki
            // and find that we're still logged in

            $this->setLoggedOutCookie( time(), $request ); // Not for this class; nah, seems OK
            $this->unpersistSession( $request ); // Does not work
            $this->logger->info(
                "MARKER: No current WordPress login, killing MediaWiki session" );

#            $sess = $request->getSession();
#            $id = $this->getSessionIdFromCookie( $request );

#            $foo = $request->getSessionId();
#            $foo = $request->getFullRequestURL();
#            $this->logger->info(
#                "MARKER: Got Session ID " . gettype($foo) . " value " . $foo);

#            $this->logger->idnfo(
#                "MARKER: my cookie name " . $this->sessionCookieName);

            return null; // XXX
        }

        $this->logger->info( "MARKER: Attempting to get userInfo " );

        $userInfo = UserInfo::newFromName( $user->user_login, true );
        // XXX How do we know userInfo is valid with MediaWiki?
        // isAnon() returns true or equivalently isRegistered()
        // returns false.
        $this->logger->info( "MARKER: Got userInfo " . $userInfo );

        if ( $this->sessionCookieName === null ) {
            // Come here when logged in to WordPress, but not
            // MediaWiki.  Can trigger this by logging out from
            // MediaWiki while logged in to WordPress.
            $this->logger->info( "MARKER: BRANCH 1: " . $user->user_login );

            $id = $this->hashToSessionId( $user->user_login );
            $persisted = false;
            $forceUse = true;

#            return null;
        } else {
            $this->logger->info( "MARKER: BRANCH 2" );

            $id = $this->getSessionIdFromCookie( $request );
            $persisted = $id !== null;
            $forceUse = false;
        }

        // XXX Ideally: specify the groups in WordPress, and override
        // theme here!  See
        // https://www.mediawiki.org/wiki/Manual:User_rights

#        $user = $userInfo->getUser();
#        foreach ( $user->getGroups() as $t ) {
#            $this->logger->info( "MARKER: See a thing of " . $t . " userID is " . $user->getId());
#        }


        return new SessionInfo( SessionInfo::MAX_PRIORITY, [
            'provider' => $this,
            'id' => $id,
            'userInfo' => $userInfo,
            'persisted' => $persisted,
            'forceUse' => $forceUse,
        ] );
    }

    // XXX Defining this empty re-enables the logout link, but why?
    // Then, logging out will kill the MediaWiki session, but not the
    // WordPress ditto.


    // XXX Only now notice: "Logging out is not possible when using
    // WPMWSessionProvider sessions"
/*
    public function refreshSessionInfo(
        SessionInfo $info, WebRequest $request, &$metadata ) {
        $this->logger->info( "MARKER: in refreshSessionInfo()" );


        // Logout function points to
        // https://cryoem.ucla.edu/mediawiki/index.php?title=Special:UserLogout&returnto=Special%3ASpecialPages&logoutToken=a5d845dfbdc4dbbcd667c0faa467e1ee5ea13f2b%2B%5C

#        $userInfo = $info->getUserInfo();
#        $user = $userInfo->getUser();
#        $token = $user->getEditToken( 'logoutToken' );

        // XXX Need the token here, somehow.  Otherwise will have to
        // click twice!

        $url = "Special:Userlogout";
        Hooks::register(
            'PersonalUrls',
            function ( &$personalurls ) use ( $url, $metadata ) {
                if ( $url instanceof Closure ) {
                    $url = call_user_func( $url, $metadata );
                }
                $internal = Title::newFromText( $url );

                if ( $internal && $internal->isKnown() ) {
                    $url = $internal->getLinkURL();
                }

#                $internal = Title::newFromText( 'Special:Userlogout' );
#                $url = $internal->getLinkURL();

                $personalurls[ 'logout' ] = [
                    'href' => $url,
                    'text' => wfMessage( 'pt-userlogout' )->text(),
                    'active'=>false
                ];
                return true;
            }
        );

        Hooks::register(
            'UserLogoutComplete',
            function() use ( $url ) {
                wp_logout();
#                echo "MARKER logoutcomplete";
                global $wgOut;
                $wgOut->redirect( $url );
                return true;
            }
        );
        return true;
*/

        return true;
    }


    // XXX Stuff for testing below
    public function unpersistSession( WebRequest $request ) {
        // This is called on logout

        $this->logger->info( "MARKER: unpersistSession()" );

        wp_logout();

        return parent::unpersistSession( $request );
    }

    public function setLoggedOutCookie( $loggedOut, WebRequest $request ) {
        // called before displaying the login-stuff when nobody is logged in
        $this->logger->info( "MARKER: setLoggedOutCookie()" );
        return parent::setLoggedOutCookie( $loggedOut, $request );
    }
}
