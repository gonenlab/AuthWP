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

/**
 * for provideSessionInfo(): apparently cannot get this into
 * extension.json, and how to credit whoever wrote this?  Others?
 *
 * MediaWiki cookie-based session provider interface
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @file
 * @ingroup Session
 */


#use MediaWiki\Session\SessionProvider;
use MediaWiki\MediaWikiServices;
#use MediaWiki\Session\CookieSessionProvider;
use MediaWiki\Session\ImmutableSessionProviderWithCookie;
use MediaWiki\Session\SessionInfo;
use MediaWiki\Session\SessionManager;
use MediaWiki\Session\UserInfo;


// Load
#require_once( '../wp-load.php' );
$config = MediaWikiServices::getInstance()
        ->getConfigFactory()
        ->makeConfig( 'WPMW' );
require_once(
    $config->get( 'WPMWPath' ) . DIRECTORY_SEPARATOR . 'wp-load.php' );


/* A lot of documentation at
 * https://doc.wikimedia.org/mediawiki-core/master/php/classMediaWiki_1_1Session_1_1SessionProvider.html
 */
/* class WPMWSessionProvider extends CookieSessionProvider { */
class WPMWSessionProvider extends ImmutableSessionProviderWithCookie {
    public function __construct( $params = [] ) {
        parent::__construct( $params );

        $config = MediaWikiServices::getInstance()
                ->getConfigFactory()
                ->makeConfig( 'WPMW' );

        $this->priority = $config->get( 'WPMWPriority' );
        if ( $this->priority < SessionInfo::MIN_PRIORITY ||
             $this->priority > SessionInfo::MAX_PRIORITY ) {
            throw new \InvalidArgumentException(
                __METHOD__ . ": Invalid priority" );
        }

        \Hooks::register( 'SessionCheckInfo', [ $this, 'onSessionCheckInfo' ]);
        \Hooks::register( 'UserLogout', [ $this, 'onUserLogout' ]);
    }


    // This re-enables the logout button.
    public function canChangeUser() {
        return true;
    }


    // The logout button only appears when logging in from MW, not WP
    //
    // XXX Would be more elegant if the the provider could make a
    // "session" without the MW stuff in it.  Then, the next session
    // provider would not be able to handle it either.  Can that me
    // done with SessionManager from AuthProvider somehow?  If this is
    // not there, users will also be prompted to confirm (submit)
    // logout after clicking the "Log out" button.  This makes sense:
    // log in to MW as Wiki admin, log in to WP as regular user, then
    // MW user is regular user.  Log out regular user (either from MW
    // or WP), then MW user is Wiki admin again.
    public static function onSessionCheckInfo(
        &$reason, $info, $request, $metadata, $data) {

        $userinfo = $info->getUserInfo();
        $username = $userinfo->getName();
        if ( !username_exists( $username ) ) {
            // WP does not know about the user.  Assume it's OK.
            return true;
        }

        // WP knows about user, so user must be logged in
        $wp_user = wp_get_current_user();
        if ( $wp_user->exists() ) {
            $wp_canonical_name =  User::getCanonicalName(
                $wp_user->user_login, 'usable' );

            if ( $wp_canonical_name == $username ) {
                return true;
            }
        }

        $reason = "Rejected session for " . $userinfo->getName();
        return false;
    }


    // Log out user from WordPress before logging out of MediaWiki
    public static function onUserLogout( &$user ) {
        wp_logout();
        return true;
    }


    // From SessionProvider's provideUserInfo() documentation: "If no
    // session exists for the request, return null.  Otherwise return
    // a SessionInfo object identifying the session."
    //
    // This closely follows provideSessionInfo() from
    // https://doc.wikimedia.org/mediawiki-core/master/php/CookieSessionProvider_8php_source.html.
    // XXX Note that in the credits, somehow.
    public function provideSessionInfo( WebRequest $request ) {
        /// From
        /// https://www.mediawiki.org/wiki/Manual:SessionManager_and_AuthManager/SessionProvider_examples
        /// --- This switches back to the
        /// ImmuatebleSessionProviderWithCookie, but that disables the
        /// logout button! Does everything else work? Just switching
        /// the class back breaks login.  Also, logging out from
        /// WordPress does not log out the MediaWiki user (but there
        /// is a logout button again).
        $wp_user = wp_get_current_user();
        if ( !$wp_user->exists() ) {
            $this->logger->info( "No WP user: ");
            return null;
        }

        $username =  User::getCanonicalName( $wp_user->user_login, 'usable' );
        $userInfo = UserInfo::newFromName( $username, true );

        $this->logger->info(
            "WP user: " . $wp_user->user_login . " MW user " . $username );

        if ( $this->sessionCookieName === null ) {
            $id = $this->hashToSessionId( $username );
            $persisted = false;
            $forceUse = true;

            $this->logger->info(
                "No sessionCookieName, ID " . $id . " other " );

        } else {
            $this->logger->info( "Have sessionCookieName" );

            $id = $this->getSessionIdFromCookie( $request );
            $persisted = $id !== null;
            $forceUse = false;
        }

#        $persisted = false;
#        $forceUse = false;

#        $persisted = false;
#        $forceUse = true;

        // This works?! But why? Do any of the other combinations
        // work? Only works when logged in from WordPress?
#        $persisted = true;
#        $forceUse = false;

#        $persisted = true;
#        $forceUse = true;

#        return new SessionInfo( SessionInfo::MAX_PRIORITY, [
        return new SessionInfo( $this->priority, [
            'provider' => $this,
            'id' => $id,
            'userInfo' => $userInfo,
            'persisted' => $persisted,
            'forceUse' => $forceUse,
        ] );


        /*** OLD CODE BELOW ***/

        $sessionId = $this->getCookie(
            $request, $this->params['sessionName'], '' );
        $info = [
            'provider' => $this,
            'forceHTTPS' => $this->getCookie( $request, 'forceHTTPS', '', false)
        ];
        if ( SessionManager::validateSessionId( $sessionId ) ) {
            $info['id'] = $sessionId;
            $info['persisted'] = true;
        }


        // Cannot fail (return null) here, because user may be logged
        // in to MediaWiki but not WordPress.  The user may not even
        // have a WordPress account (e.g. MediaWiki administrator).
        $wp_user = wp_get_current_user();
        if ( $wp_user->exists() ) {
            $wp_canonical_name =  User::getCanonicalName(
                $wp_user->user_login, 'usable' );
            $this->logger->info(
                "MARKER: canonical WP name: " . $wp_canonical_name );
        } else {
            $this->logger->info( "MARKER: no canonical WP name" );
        }

        list( $userId, $userName, $token ) = $this->getUserInfoFromCookies(
            $request );
        if ( $userId !== null ) {
            $this->logger->info(
                "MARKER have userId: " . $userId . " userName " . $userName );

            // If the user exists in WordPress but is not logged in,
            // kill the MediaWiki cookie.  It does not matter whether
            // the cookie is valid session or not.  This is not
            // working: see this message, but can still access
            // MediaWiki, but only for one page!
            if ( username_exists($userName) ) {
                if ( !isset($wp_canonical_name) ||
                     $wp_canonical_name !== $userName) {
                    $this->logger->info(
                        "MARKER WordPress user " . $userName .
                        " not logged in; logging out of MediaWiki" );
                    $this->unpersistSession( $request );
                    return null;
                }
            }

            // If there is a UserID cookie, the user must already be
            // provisioned.
            try {
                $userInfo = UserInfo::newFromId( $userId );
            } catch ( \InvalidArgumentException $ex ) {
                $this->logger->info( "MARKER caught exception" );
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

                // Edge allows us to pass when we go through here, but
                // not Firefox.
                $this->logger->info( "MARKER setting persisted" );

                $userInfo = $userInfo->verified();
                $info['persisted'] = true; // If we have user+token, it should be
            } elseif ( isset( $info['id'] ) ) {
                // XXX Set persisted here to avoid MediaWiki logout
                // after inactivity?  Why will this not grant us
                // rights to go on (if we pass through here, we still
                // need to log back on)? This is where we come after
                // logging in to MediaWiki.
                //
                // Get "Unverified user provided and no metadata to
                // auth it" after going through here.  From
                // https://phabricator.wikimedia.org/T158367: failed
                // cookie authentication attempts (e.g. session
                // timeout).
                //
                // After a reload, see " Wrong provider
                // WPMWSessionProvider !==
                // MediaWiki\Session\CookieSessionProvider", then
                // second reload logs us in...
                $this->logger->info( "MARKER persist here 1?  Verify?" );

                $info['userInfo'] = $userInfo;
            } else {
                // No point in returning, loadSessionInfoFromStore() will
                // reject it anyway.
                $this->logger->info( "MARKER persist here 1.5?" );
                return null;
            }

            // Why do we get "Login required" when we get here?
            $this->logger->info( "MARKER first clause, the end" );

#            return new SessionInfo( $this->priority, $info );

        } elseif ( isset( $info['id'] ) ) {
            // Don't get here...
            //
            // YES WE DO! We get here after creating a MediaWiki user
            // externally (e.g. in WordPress), then accessing
            // MediaWiki.  User must be registered if we get here...
            //
            // INCONCLUSIVE: XXX TEST AGAIN!
            //
            // We do get here if we're creating a new user in
            // MediaWiki, and want to create that user in WordPress,
            // too!  No, zap that last comment...
            //
            // But we do get here if we try to join the wiki
            //
            // No, I think we're all good
            //
            // No, again!  Get here after session is expired?  Logged
            // in to MediaWiki and did NOT check the "keep me logged
            // in" checkbox?

#            $this->logger->info(
#                "MARKER: auto-creating 0 (" . $wp_canonical_name . ")..." );
            $this->logger->info( "MARKER: auto-creating 0..." );

            // If the MediaWiki session is expired, but the WordPress
            // session is still valid, renew the MediaWiki session.
            // XXX Try without this bit and logging in AND checking
            // the "keep me logged in" box... I'm guessing this should
            // not be needed, then.  XXX Could possibly move the
            // "isset($wp_canonical_name)" clause above this, and test
            // for existence of MediaWiki user regardless of session
            // status, but that call for another complete round of
            // testing...
            if ( isset($wp_canonical_name) ) {
                $this->logger->info("MARKER: auto-creating 0.5...");

                $info['userInfo'] = UserInfo::newFromName(
                    $wp_canonical_name, true );
                if ( $info['userInfo']->getUser()->getId() != 0 ) { // XXX added this clause

                    $this->logger->info(
                        "MARKER: auto-creating 1 for " . $wp_canonical_name .
                        "..." );

                    // This path still does not grant us access back
                    // in...  we get "requested without UserID
                    // cookie"; how can that possibly happen?
                    return new SessionInfo( $this->priority, $info ); // if this is kept, should not return here, but fall through to the end

                    $this->logger->info("MARKER: auto-creating NOTREACHED!");

                    return $info;
                    return $userInfo;
                }
#                return null; // Return anonymous below instead.
            }


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
            $info['userInfo'] = UserInfo::newAnonymous();

#            return new SessionInfo( $this->priority, $info );
        } elseif ( isset( $wp_canonical_name ) ) {
            // Logged into WordPress, but there is no MediaWiki cookie
            // or session.  If there is no MediaWiki account (and
            // 'autocreate' is enabled) one will be created from the
            // UserInfo set up here.
            //
            // From SessionProvider's provideSessionInfo()
            // documentation: "The SessionProvider must not attempt to
            // auto-create users.  MediaWiki will do this later (when
            // it's safe) if the chose session has a user with a valid
            // name, but no ID."
            //
            // From AuthManager::autoCreateUser() documentation:
            // SessionProviders can invoke [auto-creation] by
            // returning a SessionInfo with the username of a
            // non-existing user from provideSessionInfo().
            //
            // Get here on the first round (when logged in to
            // WordPress, but no MediaWiki account); then go to the
            // above "auto-creating..."
            $this->logger->info("MARKER: auto-creating 2...");

            $userInfo = UserInfo::newFromName( $wp_canonical_name, true );

            // The bit below only needed if there is no MediaWiki
            // user...  We also get here after the MediaWiki session
            // has expired, but the WordPress session is still around.
#            $user = $userInfo->getUser(); // XXX Should not be commented
#            $user->setEmail( $wp_user->user_email ); // XXX Should not be commented
#            $user->setRealName( $wp_user->display_name ); // XXX Should not be commented

            $this->logger->info("MARKER: auto-creating 3...");

            // Would not understand if this happens... But after
            // passing here, we are logged back in!  Need the
            // hashToSessionId() thing?
            $this->logger->info( "MARKER persist here 2?" );

            $info['userInfo'] = $userInfo;

#            $info['id'] = $this->hashToSessionId( $userInfo->getName() );

#            return new SessionInfo( $this->priority, $info );

        } else {
            // No session ID, no user, and no WordPress login.  This
            // is the same as an empty session, so there's no point.

#            $this->logger->info("MARKER: auto-creating 4...");
#            $info['userInfo'] = UserInfo::newAnonymous();

            return null;
        }

        return new SessionInfo( $this->priority, $info );

        return null;
    }
}
