<?php
// AuthWP.php
// MediaWiki extension to delegate authentication and user management
// to a local Wordpress installation.
// See http://ciarang.com/wiki/page/WPMW for more information.
// Version 0.3.1
// Copyright (C) 2008-13 Ciaran Gultnieks <ciaran@ciarang.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

if(!defined('MEDIAWIKI')) {
    die('Not an entry point.');
}

// Relative path to Wordpress installation. In the default '..' we
// have MediaWiki installed in a 'wiki' directory off the main
// Wordpress root.
$WP_relpath=isset($wgAuthWPRelPath)?$wgAuthWPRelPath:'..';


// We'll derive our class from MediaWiki's AuthPlugin class...
require_once("$IP/includes/AuthPlugin.php");


// Bootstrap Wordpress. This seems rather foolish since surely the
// names of things are bound to clash somewhere, but we want to be
// able to handle everything as if Wordpress was doing it natively
// including respecting any plugins that might be in place.
if(php_sapi_name() != 'cli') {
	require($WP_relpath.'/wp-load.php');
	require($WP_relpath.'/wp-includes/registration.php');
}

// Wordpress has escaped all these in wp-settings.php - we need to
// unescape them again if they weren't meant to be escaped.
if(php_sapi_name() != 'cli' && !get_magic_quotes_gpc()) {
	$_GET    = stripslashes_deep($_GET   );
	$_POST   = stripslashes_deep($_POST  );
	$_COOKIE = stripslashes_deep($_COOKIE);
}

$wgExtensionCredits['other'][] = array(
	'path' => __FILE__,
	'name' => 'WPMW',
	'version' => '0.3.1',
	'author' => 'Ciaran Gultnieks',
	'url' => 'https://www.mediawiki.org/wiki/Extension:WPMW',
        'descriptionmsg' => 'Provides WordPress login integration',
);

// Handler for the MediaWiki UserLoadFromSession hook. Allows users
// already signed in to Wordpress to be automatically signed in to
// MediaWiki. Always returns true, but sets $result to true if auth
// has been done.
function AuthWPUserLoadFromSession($user, &$result) {

        // Abort in cli mode. Seems like it shouldn't be necessary
        // but some cli scripts to end up here for whatever bizarre
        // reason - runjobs is an example.
        if(php_sapi_name() == 'cli')
            return true;

	// Is there a Wordpress user with a valid session?
	$wpuser=wp_get_current_user();
	if(!$wpuser->ID)
		return true;

	$u=User::newFromName($wpuser->user_login);
	if(!$u)
		wp_die("Your username '".$wpuser->user_login."' is not a valid MediaWiki username");
	if(0==$u->getID()) {
		$u->addToDatabase();
		$u->setToken();
	}
	$id=User::idFromName($wpuser->user_login);
	if(!$id) {
		wp_die("Failed to get ID from name '".$wpuser->user_login."'");
		return true;
	}
	if($id==0) {
		wp_die("Wikipedia '".$wpuser->user_login."' was not found.");
		return true;
	}
	$user->setID($id);
	$user->loadFromId();
	wfSetupSession();	
	$user->setCookies();

	// Set these to ensure synchronisation with WordPress...
	$user->setEmail($wpuser->user_email);
	$user->setRealName($wpuser->user_nicename);

	$user->saveSettings();
	$result=true;

	return true;
}

// Handler for the MediaWiki UserLogout hook.
function AuthWPUserLogout(&$user) {
	// Log out of Wordpress as well...
	wp_logout();
	return true;
}

class AuthWP extends AuthPlugin {

	// Constructor
	function AuthWP(){

		// Add hooks...
		global $wgHooks;
		$wgHooks['UserLoadFromSession'][]='AuthWPUserLoadFromSession';
		$wgHooks['UserLogout'][] = 'AuthWPUserLogout';

	}


	// MediaWiki API HANDLER
	// See if the given user exists - true if so, false if not...
	function userExists($username) {
		return username_exists($username);
	}

	// MediaWiki API HANDLER
	// Handle authentication, returning true if the given credentials
	// are good, or false if they're bad.
	function authenticate($username,$password) {
		$credentials=array('user_login'=>$username,'user_password'=>$password);
		if(is_wp_error(wp_signon($credentials,false)))
			return false;
		return true;
	}

	// MediaWiki API HANDLER
	// Modify the login template...
	function modifyUITemplate(&$template) {
		$template->set('create',false);
		$template->set('usedomain',false);
		$template->set('useemail',true);
	}

	// MediaWiki API HANDLER
	// Always return true - tells it to automatically create a local
	// account when asked to log in a user that doesn't exist locally.
	function autoCreate() {
		return true;
	}

	// MediaWiki API HANDLER
	function allowEmailChange() {
		// No - change it via the WordPress interface only.
		return false;
	}

	// MediaWiki API HANDLER
	function allowRealNameChange() {
		// No - change it via the WordPress interface only.
		return false;
	}

	// MediaWiki API HANDLER
	// Always return true - users can change their passwords from
	// MediaWiki - we'll hash them and update the Wordpress DB.
	function allowPasswordChange() {
		return true;
	}

	// MediaWiki API HANDLER
	// Set a new password for the given user...
	function setPassword($user,$password) {
		$wpuser=get_userdatabylogin($user->mName);
		if(!$wpuser)
			return false;
		wp_set_password($password,$wpuser->user_id);
		return true;
	}

	// MediaWiki API HANDLER
	// Update the details of a user that's logging in - i.e. fill in any
	// details we can retrieve from the Wordpress user details...
	function updateUser(&$user) {
		$wpuser=get_userdatabylogin($user->mName);
		if(!$wpuser)
			return false;
		$user->setEmail($wpuser->user_email);
		$user->setRealName($wpuser->user_nicename);
		$user->saveSettings();
		return true;
	}

	// MediaWiki API HANDLER
	// Update user details in Wordpress database...
	function updateExternalDB($user) {
		// Not doing anything here (yet?)
		return true;
	}

	// MediaWiki API HANDLER
	// Add a user created in MediaWiki to the Wordpress database...
	function addUser($user,$password) {
		wp_create_user($user->mName,$password,$user->mEmail);
		return true;
	}

	// MediaWiki API HANDLER
	// Just return true meaning that logins can only be authenticated in
	// this module, and not checked against the mediawiki db...
	function strict() {
		return true;
	}

	// MediaWiki API HANDLER
	// As with strict(), only authenticate through this plugin.
	function strictUserAuth($username) {
		return true;
	}

	// MediaWiki API HANDLER
	// We can create external accounts so always return true...
	function canCreateAccounts() {
		return true;
	}

}
?>
