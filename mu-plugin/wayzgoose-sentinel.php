<?php
/**
 * Plugin Name: Wayzgoose Sentinel
 * Plugin URI:  https://github.com/Erik-Debye/wayzgoose-for-pressable
 * Description: Posts an alert to a Slack or Discord webhook the moment a user is created with, promoted to, demoted from, or deleted while holding a privileged role. Includes who did it and from where. Installed account-wide by Wayzgoose for Pressable.
 * Version:     1.0.0
 * Author:      Erik Debye
 * License:     MIT
 *
 * Configuration (set by Wayzgoose through WP-CLI, or by hand):
 *   WAYZGOOSE_SENTINEL_WEBHOOK  constant in wp-config.php, or option wayzgoose_sentinel_webhook
 *   WAYZGOOSE_SENTINEL_ROLES    comma-separated roles to watch (default "administrator"),
 *                               or option wayzgoose_sentinel_roles
 *
 * Test from WP-CLI:  wp eval 'do_action("wayzgoose_sentinel_test");'
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( class_exists( 'Wayzgoose_Sentinel' ) ) {
	return;
}

final class Wayzgoose_Sentinel {

	const VERSION = '1.0.0';

	/** @var array<int, string> user ID => role, for creations seen via set_user_role before user_register. */
	private static $pending_creations = array();

	public static function boot() {
		add_action( 'wayzgoose_sentinel_test', array( __CLASS__, 'on_test' ) );

		if ( ! self::webhook() ) {
			return;
		}
		add_action( 'set_user_role', array( __CLASS__, 'on_set_user_role' ), 10, 3 );
		add_action( 'add_user_role', array( __CLASS__, 'on_add_user_role' ), 10, 2 );
		add_action( 'remove_user_role', array( __CLASS__, 'on_remove_user_role' ), 10, 2 );
		add_action( 'user_register', array( __CLASS__, 'on_user_register' ), 10, 1 );
		add_action( 'delete_user', array( __CLASS__, 'on_delete_user' ), 10, 3 );
		add_action( 'grant_super_admin', array( __CLASS__, 'on_grant_super_admin' ) );
		add_action( 'revoke_super_admin', array( __CLASS__, 'on_revoke_super_admin' ) );
		add_action( 'shutdown', array( __CLASS__, 'flush_pending' ) );
	}

	// ----- Configuration -----

	public static function webhook() {
		if ( defined( 'WAYZGOOSE_SENTINEL_WEBHOOK' ) && WAYZGOOSE_SENTINEL_WEBHOOK ) {
			return (string) WAYZGOOSE_SENTINEL_WEBHOOK;
		}
		$opt = get_option( 'wayzgoose_sentinel_webhook', '' );
		return is_string( $opt ) ? trim( $opt ) : '';
	}

	/** @return string[] */
	public static function watched_roles() {
		$raw = defined( 'WAYZGOOSE_SENTINEL_ROLES' ) && WAYZGOOSE_SENTINEL_ROLES
			? WAYZGOOSE_SENTINEL_ROLES
			: get_option( 'wayzgoose_sentinel_roles', 'administrator' );
		$roles = array_filter( array_map( 'trim', explode( ',', strtolower( (string) $raw ) ) ) );
		return $roles ? array_values( $roles ) : array( 'administrator' );
	}

	private static function is_watched( $roles ) {
		foreach ( (array) $roles as $role ) {
			if ( in_array( strtolower( (string) $role ), self::watched_roles(), true ) ) {
				return true;
			}
		}
		return false;
	}

	// ----- Hooks -----

	/**
	 * Fires from WP_User::set_role(). During wp_insert_user() it fires with an
	 * empty $old_roles just before user_register, so creations are parked and
	 * reported once by on_user_register (or flushed at shutdown if no
	 * user_register follows, which means an existing role-less user was promoted).
	 */
	public static function on_set_user_role( $user_id, $role, $old_roles ) {
		$old_roles = (array) $old_roles;
		if ( empty( $old_roles ) ) {
			self::$pending_creations[ (int) $user_id ] = (string) $role;
			return;
		}
		$was = self::is_watched( $old_roles );
		$now = self::is_watched( array( $role ) );
		if ( ! $was && ! $now ) {
			return;
		}
		$event = $now && ! $was ? 'promoted' : ( $was && ! $now ? 'demoted' : 'role changed' );
		self::alert( $event, $user_id, array(
			'From' => implode( ', ', $old_roles ),
			'To'   => (string) $role,
		) );
	}

	/** Fires from WP_User::add_role(): an extra role added alongside existing ones. */
	public static function on_add_user_role( $user_id, $role ) {
		if ( ! self::is_watched( array( $role ) ) ) {
			return;
		}
		self::alert( 'promoted', $user_id, array( 'Added role' => (string) $role ) );
	}

	public static function on_remove_user_role( $user_id, $role ) {
		if ( ! self::is_watched( array( $role ) ) ) {
			return;
		}
		self::alert( 'demoted', $user_id, array( 'Removed role' => (string) $role ) );
	}

	public static function on_user_register( $user_id ) {
		unset( self::$pending_creations[ (int) $user_id ] );
		$user = get_userdata( $user_id );
		if ( ! $user || ! self::is_watched( $user->roles ) ) {
			return;
		}
		self::alert( 'created', $user_id, array( 'Role' => implode( ', ', $user->roles ) ) );
	}

	/** Fires before deletion; $user is passed since WordPress 5.5. */
	public static function on_delete_user( $user_id, $reassign = null, $user = null ) {
		if ( ! $user instanceof WP_User ) {
			$user = get_userdata( $user_id );
		}
		if ( ! $user || ! self::is_watched( $user->roles ) ) {
			return;
		}
		$extra = array( 'Had role' => implode( ', ', $user->roles ) );
		if ( $reassign ) {
			$to = get_userdata( $reassign );
			$extra['Content reassigned to'] = $to ? $to->user_login : (string) $reassign;
		}
		self::alert( 'deleted', $user_id, $extra, $user );
	}

	public static function on_grant_super_admin( $user_id ) {
		self::alert( 'promoted', $user_id, array( 'To' => 'super admin (network)' ) );
	}

	public static function on_revoke_super_admin( $user_id ) {
		self::alert( 'demoted', $user_id, array( 'From' => 'super admin (network)' ) );
	}

	/** Creations parked by on_set_user_role that never reached user_register. */
	public static function flush_pending() {
		foreach ( self::$pending_creations as $user_id => $role ) {
			if ( self::is_watched( array( $role ) ) ) {
				self::alert( 'promoted', $user_id, array( 'To' => $role, 'Note' => 'user previously had no role' ) );
			}
		}
		self::$pending_creations = array();
	}

	public static function on_test() {
		$hook = self::webhook();
		if ( ! $hook ) {
			if ( defined( 'WP_CLI' ) && WP_CLI ) {
				WP_CLI::error( 'Wayzgoose Sentinel: no webhook configured on this site.' );
			}
			return;
		}
		self::send( self::payload(
			'test',
			'Wayzgoose Sentinel is active on ' . self::site_label(),
			array( 'Watching roles' => implode( ', ', self::watched_roles() ), 'Version' => self::VERSION ),
			self::actor()
		) );
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			WP_CLI::success( 'Wayzgoose Sentinel: test message sent.' );
		}
	}

	// ----- Building and sending alerts -----

	private static function alert( $event, $user_id, $extra = array(), $user = null ) {
		if ( ! $user instanceof WP_User ) {
			$user = get_userdata( $user_id );
		}
		$login = $user ? $user->user_login : ( 'user #' . (int) $user_id );
		$verb  = array(
			'created'      => 'created with a privileged role',
			'promoted'     => 'promoted to a privileged role',
			'demoted'      => 'removed from a privileged role',
			'role changed' => 'moved between privileged roles',
			'deleted'      => 'deleted while holding a privileged role',
		);
		$title = sprintf( 'User %s %s on %s', $login, isset( $verb[ $event ] ) ? $verb[ $event ] : $event, self::site_label() );

		$fields = array(
			'User' => $user
				? sprintf( '%s (ID %d)%s', $user->user_login, $user->ID, $user->user_email ? ' · ' . $user->user_email : '' )
				: 'ID ' . (int) $user_id,
		);
		if ( $user && $user->user_registered ) {
			$fields['Registered'] = $user->user_registered;
		}
		foreach ( $extra as $k => $v ) {
			$fields[ $k ] = $v;
		}
		if ( $user ) {
			$fields['Edit user'] = admin_url( 'user-edit.php?user_id=' . (int) $user->ID );
		}
		self::send( self::payload( $event, $title, $fields, self::actor() ) );
	}

	/** Who did it, and from where. */
	private static function actor() {
		$who = '';
		if ( function_exists( 'wp_get_current_user' ) ) {
			$cu = wp_get_current_user();
			if ( $cu && $cu->exists() ) {
				$who = sprintf( '%s (ID %d)%s', $cu->user_login, $cu->ID, $cu->user_email ? ' · ' . $cu->user_email : '' );
			}
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			$via = 'WP-CLI';
		} elseif ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			$via = 'WP-Cron';
		} elseif ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			$via = 'REST API';
		} elseif ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			$via = 'XML-RPC';
		} elseif ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
			$via = 'admin-ajax';
		} else {
			$via = 'web request';
		}
		if ( ! $who ) {
			$who = ( 'WP-CLI' === $via || 'WP-Cron' === $via ) ? 'no logged-in user (' . $via . ')' : 'NOT LOGGED IN — investigate';
		}

		$ip = '';
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' ) as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				$ip = trim( explode( ',', (string) $_SERVER[ $key ] )[0] );
				break;
			}
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? (string) $_SERVER['REQUEST_METHOD'] : '';
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		$agent  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';

		return array(
			'By'      => $who,
			'Via'     => $via . ( $uri ? ' · ' . $method . ' ' . substr( $uri, 0, 120 ) : '' ),
			'From IP' => $ip ? $ip : 'n/a',
			'Agent'   => $agent ? substr( $agent, 0, 160 ) : 'n/a',
		);
	}

	private static function site_label() {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		return $host ? $host : get_bloginfo( 'name' );
	}

	private static function payload( $event, $title, $fields, $actor ) {
		$hook = self::webhook();
		$all  = array_merge( $fields, $actor );
		$colors = array( 'created' => 0xB0392F, 'promoted' => 0xB0392F, 'role changed' => 0xD9772C, 'demoted' => 0xC9A227, 'deleted' => 0xD9772C, 'test' => 0x2E7D4F );
		$emoji  = 'test' === $event ? '✅' : ( in_array( $event, array( 'demoted', 'deleted' ), true ) ? '🟨' : '🟥' );
		$footer = 'Wayzgoose Sentinel ' . self::VERSION . ' · ' . self::site_label();

		if ( preg_match( '#^https://(discord\.com|discordapp\.com)/api/webhooks/#i', $hook ) ) {
			$embed_fields = array();
			foreach ( $all as $name => $value ) {
				$embed_fields[] = array(
					'name'   => (string) $name,
					'value'  => substr( (string) $value, 0, 1000 ),
					'inline' => in_array( $name, array( 'From', 'To', 'Role', 'Added role', 'Removed role', 'Had role', 'From IP', 'Registered' ), true ),
				);
			}
			return array(
				'embeds' => array( array(
					'title'       => substr( $emoji . ' ' . $title, 0, 256 ),
					'color'       => isset( $colors[ $event ] ) ? $colors[ $event ] : 0x8A94A0,
					'fields'      => array_slice( $embed_fields, 0, 25 ),
					'footer'      => array( 'text' => $footer ),
					'timestamp'   => gmdate( 'c' ),
				) ),
			);
		}

		if ( preg_match( '#^https://hooks\.slack\.com/#i', $hook ) ) {
			$lines = array();
			foreach ( $all as $name => $value ) {
				$lines[] = '*' . $name . ':* ' . $value;
			}
			return array(
				'text'   => $emoji . ' ' . $title,
				'blocks' => array(
					array( 'type' => 'header', 'text' => array( 'type' => 'plain_text', 'text' => substr( $emoji . ' ' . $title, 0, 150 ) ) ),
					array( 'type' => 'section', 'text' => array( 'type' => 'mrkdwn', 'text' => substr( implode( "\n", $lines ), 0, 2900 ) ) ),
					array( 'type' => 'context', 'elements' => array( array( 'type' => 'mrkdwn', 'text' => $footer ) ) ),
				),
			);
		}

		return array(
			'text'   => $title,
			'event'  => $event,
			'site'   => home_url(),
			'at'     => gmdate( 'c' ),
			'fields' => $all,
			'source' => 'wayzgoose-sentinel/' . self::VERSION,
		);
	}

	private static function send( $payload ) {
		$hook = self::webhook();
		if ( ! $hook ) {
			return;
		}
		wp_remote_post( $hook, array(
			'timeout'  => 5,
			'blocking' => false,
			'headers'  => array( 'Content-Type' => 'application/json' ),
			'body'     => wp_json_encode( $payload ),
		) );
	}
}

Wayzgoose_Sentinel::boot();
