// Wayzgoose session check. Run on a site by Wayzgoose through WP-CLI
// (wp eval) when the audit finds a privileged-user change, to answer
// "which WordPress user could have done it?" without a plugin.
//
// WordPress core keeps, for every logged-in session, the IP, user agent and
// login time (usermeta session_tokens), and for every application password
// its last-used time and IP. This script lists users able to change roles,
// finds their sessions and application-password uses that overlap the window
// since the previous audit, marks the ones whose IP matches a request from the
// web server log, and posts the result to the webhook.
//
// Rules for this file (it is sent as one line inside single quotes):
//   - no single quotes anywhere, including comments
//   - only line comments starting with //, which are stripped
//   - $args[0] is base64 JSON: {webhook, since, until, ips[], site, event}

$cfg = json_decode(base64_decode($args[0]), true);
if (!is_array($cfg) || empty($cfg["webhook"])) { WP_CLI::error("Wayzgoose: missing arguments"); }
$since = (int) $cfg["since"];
$until = (int) $cfg["until"];
$ips = array_map("strval", isset($cfg["ips"]) && is_array($cfg["ips"]) ? $cfg["ips"] : array());
$label = isset($cfg["site"]) && $cfg["site"] ? $cfg["site"] : wp_parse_url(home_url(), PHP_URL_HOST);
$event = isset($cfg["event"]) ? $cfg["event"] : "a privileged-user change";

$actors = get_users(array("capability__in" => array("promote_users", "create_users", "edit_users", "delete_users"), "fields" => "all"));
$strong = array();
$active = array();
foreach ($actors as $u) {
	$sessions = WP_Session_Tokens::get_instance($u->ID)->get_all();
	foreach ($sessions as $s) {
		$login = isset($s["login"]) ? (int) $s["login"] : 0;
		$exp = isset($s["expiration"]) ? (int) $s["expiration"] : 0;
		if ($login > $until || $exp < $since) { continue; }
		$ip = isset($s["ip"]) ? (string) $s["ip"] : "";
		$ua = isset($s["ua"]) ? substr((string) $s["ua"], 0, 90) : "";
		$line = sprintf("%s (ID %d) · session from %s · logged in %s · %s", $u->user_login, $u->ID, $ip ? $ip : "unknown IP", gmdate("Y-m-d H:i", $login) . " UTC", $ua);
		if ($ip && in_array($ip, $ips, true)) { $strong[] = $line; } else { $active[] = $line; }
	}
	if (class_exists("WP_Application_Passwords")) {
		foreach (WP_Application_Passwords::get_user_application_passwords($u->ID) as $ap) {
			$used = isset($ap["last_used"]) ? (int) $ap["last_used"] : 0;
			if (!$used || $used < $since || $used > $until) { continue; }
			$ip = isset($ap["last_ip"]) ? (string) $ap["last_ip"] : "";
			$line = sprintf("%s (ID %d) · application password \"%s\" used %s from %s", $u->user_login, $u->ID, $ap["name"], gmdate("Y-m-d H:i", $used) . " UTC", $ip ? $ip : "unknown IP");
			if ($ip && in_array($ip, $ips, true)) { $strong[] = $line; } else { $active[] = $line; }
		}
	}
}

$window = gmdate("Y-m-d H:i", $since) . " → " . gmdate("Y-m-d H:i", $until) . " UTC";
$title = "Who could have made " . $event . " on " . $label;
$parts = array();
$parts[] = "**Window:** " . $window . ($ips ? " · request IPs: " . implode(", ", $ips) : "");
if ($strong) { $parts[] = "**Matches the request IP:**\n• " . implode("\n• ", $strong); }
if ($active) { $parts[] = ($strong ? "**Other privileged sessions active in the window:**" : "**Privileged sessions active in the window (no IP match):**") . "\n• " . implode("\n• ", array_slice($active, 0, 12)); }
if (!$strong && !$active) { $parts[] = "No user able to change roles had a session or application-password use in the window. The change likely came from WP-CLI, cron, or a direct database edit."; }
$parts[] = "_Sessions last 48 hours (14 days with Remember Me); " . count($actors) . " users can change roles on this site._";
$text = implode("\n\n", $parts);

$hook = $cfg["webhook"];
if (preg_match("#^https://(discord\\.com|discordapp\\.com)/api/webhooks/#i", $hook)) {
	$payload = array("embeds" => array(array("title" => substr("🔎 " . $title, 0, 256), "description" => substr($text, 0, 4000), "color" => $strong ? 0xB0392F : 0x8A94A0, "footer" => array("text" => "Wayzgoose session check · " . $label), "timestamp" => gmdate("c"))));
} elseif (preg_match("#^https://hooks\\.slack\\.com/#i", $hook)) {
	$payload = array("text" => $title, "blocks" => array(array("type" => "header", "text" => array("type" => "plain_text", "text" => substr("🔎 " . $title, 0, 150))), array("type" => "section", "text" => array("type" => "mrkdwn", "text" => substr(str_replace("**", "*", $text), 0, 2900)))));
} else {
	$payload = array("text" => $title, "site" => home_url(), "window" => array("since" => $since, "until" => $until), "matches" => $strong, "active" => $active, "source" => "wayzgoose-session-check");
}
$res = wp_remote_post($hook, array("timeout" => 10, "headers" => array("Content-Type" => "application/json"), "body" => wp_json_encode($payload)));
if (is_wp_error($res)) { WP_CLI::error("Wayzgoose: webhook failed: " . $res->get_error_message()); }
WP_CLI::success(sprintf("Wayzgoose: session check posted (%d matching, %d other)", count($strong), count($active)));
