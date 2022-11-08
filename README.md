<!-- -*- mode: gfm -*- -->

AuthWP is a [MediaWiki](https://www.mediawiki.org) extension that
allows authentication with [WordPress](https://wordpress.org)
credentials.  It is a rewrite
of [WPMW](https://www.mediawiki.org/w/index.php?oldid=3746476)
by [Ciaran Gultnieks](https://github.com/CiaranG) and is intended to
provide essentially the same functionality using `SessionManager` and
`AuthenticationProvider` introduced in MediaWiki 1.27.  In particular:
* A valid WordPress session allows access to MediaWiki.
  Authenticating to MediaWiki with WordPress credentials signs the
  user in to WordPress.
* Logging out from MediaWiki also logs the user out from WordPress and
  <i>vice versa</i>.
* User passwords are maintained in WordPress only, but can be changed
  from either MediaWiki or WordPress.  MediaWiki users
  <em>without</em> corresponding WordPress accounts will have their
  passwords maintained by MediaWiki.
* MediaWiki can be configured to auto-create accounts for existing
  WordPress users when they first access the wiki.  Generally, user
  management will have to be done from WordPress, but because
  MediaWiki requires a different set of attributes for its users
  (<i>e.g.</i> group membership and number of edits), it is not
  possible to do away with the MediaWiki accounts entirely.
* It is also possible to simultaneously create accounts in WordPress
  when users register for the wiki.  Because this will use WordPress
  default values for all user attributes not supplied during the
  MediaWiki registration process, users may end up with <i>e.g.</i>
  empty email addresses.  This is a potential problem because
  WordPress assumes email addresses are unique user identifiers.

See the
MediaWiki
[Extension page](https://www.mediawiki.org/wiki/Extension:AuthWP) for
further documentation.
