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
 *
 * See also https://github.com/eellak/mediawiki-wordpress-sso-extension/blob/master/AuthWP.php
 */

#use MediaWiki\Session\SessionProvider;
use MediaWiki\Session\CookieSessionProvider;
use MediaWiki\Session\SessionInfo;
use MediaWiki\Session\SessionManager;
use MediaWiki\Session\UserInfo;

// XXX Ideally, the relative path to wp-load.php should be
// configurable
require_once( '../wp-load.php' );


class WPMWSessionProvider extends CookieSessionProvider {
    // XXX Make priority configurable?
    public function __construct( $params = [] ) {
        $params += [ 'priority' => SessionInfo::MAX_PRIORITY ];
        parent::__construct( $params );
        \Hooks::register( 'UserLogout', [ $this, 'onUserLogout' ]);
    }


    // Log out user from WordPress before logging out of MediaWiki
    public function onUserLogout( &$user ) {
        $this->logger->info( "MARKER userLogout hook called" );
        wp_logout();
        return true;
    }


    // From SessionProvider's provideUserInfo() documentation: "If no
    // session exists for the request, return null.  Otherwise return
    // a SessionInfo object identifying the session."
    //
    // This closely follows
    // https://doc.wikimedia.org/mediawiki-core/master/php/CookieSessionProvider_8php_source.html
    public function provideUserInfo( WebRequest $request, $sessionId = null ) {
        list( $userId, $userName, $token ) = $this->getUserInfoFromCookies(
            $request );

        // Cannot fail (return null) here, because user may be logged
        // in to non-WP account.
        $wp_user = wp_get_current_user();
        if ( $wp_user->exists() ) {
            $wp_canonical_name =  User::getCanonicalName(
                $wp_user->user_login, 'usable' );
            $this->logger->info(
                "MARKER: canonical WP name: " . $wp_canonical_name );
        } else {
            $this->logger->info( "MARKER: no canonical WP name" );
        }

        if ( $userId !== null ) {
            $this->logger->info(
                "MARKER have userId: " . $userId . " userName " . $userName );

            // If there is a UserID cookie, the user must already be
            // provisioned.
            try {
                $userInfo = UserInfo::newFromId( $userId );
            } catch ( \InvalidArgumentException $ex ) {
                return null;
            }

            // Sanity check: the user name and ID from the UserID
            // cookie must match.
            if ( $userName !== null && $userInfo->getName() !== $userName ) {
                $this->logger->warning(
                    'Session "{session}" requested with mismatched UserID and UserName cookies.',
                    [
                        'session' => $sessionId,
                        'mismatch' => [
                            'userid' => $userId,
                            'cookie_username' => $userName,
                            'username' => $userInfo->getName(),
                        ],
                    ] );
                return null;
            }

            // If there is a token, it must be valid.  If there is no
            // token, there must be a valid session.
            if ( $token !== null ) {
                if ( !hash_equals( $userInfo->getToken(), $token ) ) {
                    $this->logger->warning(
                        'Session "{session}" requested with invalid Token cookie.',
                        [
                            'session' => $sessionId,
                            'userid' => $userId,
                            'username' => $userInfo->getName(),
                        ] );
                    return null;
                }
                $userInfo = $userInfo->verified();
#                $info['persisted'] = true; // If we have user+token,
#                                           // it should be XXX
#                                           // Commented, set outside
#                                           // this function, always
#                                           // true when this guy
#                                           // returns non-null
            } elseif ( $sessionId === null ) {
                return null;
            }


            // XXX Check must match WP user!  Fishy!  What about
            // non-WP users? Those that are not in WP as per
            // AuthenticationProvider?  If this returns null, then the
            // MediaWiki and WordPress sessions will be destroyed.
            //
            // XXX How do we know userInfo is valid with MediaWiki?
            // isAnon() returns true or equivalently isRegistered()
            // returns false.  Apparently isRegistered() cannot be
            // used to determine whether provisioning is necessary.
            $this->logger->info( "MARKER are we there yet?" );

            if ( username_exists($userName) ) {
                if (!isset($wp_canonical_name) ||
                    $wp_canonical_name != $userName) {
                    // We get here if the user has a valid MediaWiki
                    // session, but is not logged in to WordPress.
                    // Log the user out of MediaWiki?
                    $this->logger->info( "MARKER are we there yet? NULL!" );
                    $this->unpersistSession( $request );
                    return null;
                }
            }

            return $userInfo;

        } elseif ( $sessionId !== null ) {
/*
            // Don't get here...
            //
            // YES WE DO! Get here after creating a user in WordPress,
            // then accessing MediaWiki.  User must be registered if
            // we get here...
            //
            // INCONCLUSIVE: XXX TEST AGAIN!
            if ( isset($wp_canonical_name) ) {
                $this->logger->info("MARKER: auto-creating 0...");
                $userInfo = UserInfo::newFromName( $wp_canonical_name, true );
                $this->logger->info("MARKER: auto-creating 1...");
                if ( $userInfo->getUser()->getId() != 0 ) { // XXX added this clause
                    return $userInfo;
                }
            }
*/

            // No UserID cookie, so insist that the session is anonymous.
            // Note: this event occurs for several normal activities:
            // * anon visits Special:UserLogin
            // * anon browsing after seeing Special:UserLogin
            // * anon browsing after edit or preview
            $this->logger->debug(
                'Session "{session}" requested without UserID cookie',
                [
                    'session' => $sessionId,
                ] );
            return UserInfo::newAnonymous();
        }

        // Either: Have userId, but no token or no sessionID.  No
        // point in returning, loadSessionInfoFromStore() will reject
        // it anyway.
        //
        // Or: No session ID and no user is the same as an empty
        // session, so there's no point.
        //
        // recover: XXX looks like we never get here...  Yes we do!
        // auto-creation buggered without it!  But the log messages
        // never show up!  We don't pass through here if the user is
        // auto-created by explicitly logging in...  That's because
        // auto-provisioning happens elsewhere (we get here if user is
        // logged in to WordPress when MediaWiki is accessed)... Note
        // that auto-create must be enabled in the configuration file
        // to work.
        //
        // From SessionProvider's provideSessionInfo() documentation:
        // "The SessionProvider must not attempt to auto-create users.
        // MediaWiki will do this later (when it's safe) if the chose
        // session has a user with a valid name, but no ID.
        if ( isset($wp_canonical_name) ) {
#            try {
                $this->logger->info("MARKER: auto-creating 2...");

                $userInfo = UserInfo::newFromName( $wp_canonical_name, true );

                $user = $userInfo->getUser();
                $user->setEmail( $wp_user->user_email );
                $user->setRealName( $wp_user->display_name );

                $this->logger->info("MARKER: auto-creating 3...");

                return $userInfo;
/*
            } catch ( \InvalidArgumentException $ex ) {
                // XXX Expect to get here for authenticated users that
                // have not been provisioned.  Either users are
                // provisioned by AuthProvider, or they should be
                // provisioned here?  Since $wp_canonical_name is a
                // valid username, this should not throw an exception
                // for valid user, and auto-creation should happen
                // here.
                //
                // From AuthManager::autoCreateUser() documentation:
                // SessionProviders can invoke [auto-creation] by
                // returning a SessionInfo with the username of a
                // non-existing user from provideSessionInfo().
                $this->logger->info("MARKER: auto-creating 4...");
                return null;
            }
*/
        }

        return null;
    }


    public function provideSessionInfo( WebRequest $request ) {
        $this->logger->info( "MARKER: Here we go at " . $this->priority );

        $sessionId = $this->getCookie(
            $request, $this->params['sessionName'], '' );

        if ( SessionManager::validateSessionId( $sessionId ) ) {
            $userInfo = $this->provideUserInfo( $request, $sessionId );
            if ($userInfo === null) {
                $this->logger->info( "MARKER: Wednesday 1" );
                return null;
            }

#            if ( $userInfo->isAnon() ) {
#                $this->logger->info(
#                    "MARKER: " . $userInfo->getName() .
#                    " is anonymous (NOT registered)" );
#            } else {
#                $this->logger->info(
#                    "MARKER: " . $userInfo->getName() .
#                    " is NOT anonymous (registered)" );
#                $sessionId = $this->hashToSessionId( $userInfo->getName() );
#            }

        } else {
            $userInfo = $this->provideUserInfo( $request, null );
            if ($userInfo === null) {
                $this->logger->info( "MARKER: Wednesday 2" );
                return null;
            }
            $sessionId = $this->hashToSessionId( $userInfo->getName() );
        }


        // XXX Ideally: specify the groups in WordPress, and override
        // theme here!  See
        // https://www.mediawiki.org/wiki/Manual:User_rights; nah,
        // maybe control MediaWiki from WordPress directly?  Cleaner,
        // as it would be done from the theme.
#        $user = $userInfo->getUser();
#        foreach ( $user->getGroups() as $t ) {
#            $this->logger->info(
#                "MARKER: See a thing of " . $t .
#                " userID is " . $user->getId() );
#        }


        // All sessions are persisted!
        $this->logger->info(
            "MARKER: creating SessionInfo for " . $userInfo->getName() );
        return new SessionInfo( $this->priority, [
            'forceHTTPS' => $this->getCookie(
                $request, 'forceHTTPS', '', false ),
            'id' => $sessionId,
            'persisted' => true,
            'provider' => $this,
            'userInfo' => $userInfo
        ] );
    }


/*
    // unpersistSession() is called on logout.
    public function unpersistSession( WebRequest $request ) {
        $this->logger->info( "MARKER: unpersistSession()" );
#        wp_logout();
        return parent::unpersistSession( $request );
    }
*/
}
