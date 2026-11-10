// Wayzgoose config report. Run on a site by Wayzgoose through WP-CLI
// (wp eval) from the Config tab with "Deep check" on. Reads what the public
// check cannot: wp-config.php constants and the options that decide where
// the site thinks it lives, then posts a report to the webhook, flagging
// anything that disagrees with what Pressable records for the site.
//
// Rules for this file (it is sent as one line inside single quotes):
//   - no single quotes anywhere, including comments
//   - only line comments starting with //, which are stripped
//   - $args[0] is base64 JSON: {webhook, pressableUrl, staging, site}

$cfg = json_decode(base64_decode($args[0]), true);
if (!is_array($cfg) || empty($cfg["webhook"])) { WP_CLI::error("Wayzgoose: missing arguments"); }
$pressable = strtolower(preg_replace("#^www\\.#", "", parse_url("https://" . preg_replace("#^https?://#", "", (string) $cfg["pressableUrl"]), PHP_URL_HOST)));
$staging = !empty($cfg["staging"]);
$label = isset($cfg["site"]) && $cfg["site"] ? $cfg["site"] : wp_parse_url(home_url(), PHP_URL_HOST);
$bare = function ($url) { $h = parse_url((string) $url, PHP_URL_HOST); return $h ? strtolower(preg_replace("#^www\\.#", "", $h)) : ""; };
$mask = function ($v) { $v = (string) $v; return strlen($v) > 4 ? substr($v, 0, 4) . str_repeat("*", max(3, strlen($v) - 4)) : "****"; };

$c = function ($name) { return defined($name) ? constant($name) : null; };
$show = function ($v) { if ($v === null) { return "not set"; } if (is_bool($v)) { return $v ? "true" : "false"; } return (string) $v; };

$rows = array();
$rows["Environment (wp_get_environment_type)"] = wp_get_environment_type();
$rows["home option"] = get_option("home");
$rows["siteurl option"] = get_option("siteurl");
$rows["WP_HOME"] = $show($c("WP_HOME"));
$rows["WP_SITEURL"] = $show($c("WP_SITEURL"));
$rows["blog_public (search engines allowed)"] = get_option("blog_public") ? "1 (allowed)" : "0 (discouraged)";
$rows["WordPress"] = get_bloginfo("version");
$rows["PHP"] = PHP_VERSION;
$rows["Theme"] = get_option("stylesheet") . (get_option("template") !== get_option("stylesheet") ? " (child of " . get_option("template") . ")" : "");
$rows["DB_NAME"] = $mask($c("DB_NAME"));
$rows["DB_HOST"] = $mask($c("DB_HOST"));
global $table_prefix; $rows["table_prefix"] = (string) $table_prefix;
$rows["WP_DEBUG"] = $show($c("WP_DEBUG"));
$rows["WP_DEBUG_DISPLAY"] = $show($c("WP_DEBUG_DISPLAY"));
$rows["DISALLOW_FILE_MODS"] = $show($c("DISALLOW_FILE_MODS"));
$rows["DISALLOW_FILE_EDIT"] = $show($c("DISALLOW_FILE_EDIT"));
$rows["JETPACK_STAGING_MODE"] = $show($c("JETPACK_STAGING_MODE"));
$rows["WP_CACHE"] = $show($c("WP_CACHE"));
$rows["DISABLE_WP_CRON"] = $show($c("DISABLE_WP_CRON"));
$rows["WP_MEMORY_LIMIT"] = $show($c("WP_MEMORY_LIMIT"));
$rows["Multisite"] = is_multisite() ? "yes" : "no";

$flags = array();
$homeHost = $bare(get_option("home"));
if ($pressable && $homeHost && $homeHost !== $pressable) { $flags[] = "home option points at " . $homeHost . ", Pressable has " . $pressable; }
if ($c("WP_HOME") !== null && $pressable && $bare($c("WP_HOME")) !== $pressable) { $flags[] = "WP_HOME constant points at " . $bare($c("WP_HOME")); }
if ($c("WP_SITEURL") !== null && $pressable && $bare($c("WP_SITEURL")) !== $pressable) { $flags[] = "WP_SITEURL constant points at " . $bare($c("WP_SITEURL")); }
if (!$staging && preg_match("#mystagingwebsite\\.com#i", get_option("home") . " " . get_option("siteurl") . " " . $c("WP_HOME") . " " . $c("WP_SITEURL"))) { $flags[] = "a staging address is configured on this production site"; }
if (!$staging && wp_get_environment_type() !== "production") { $flags[] = "environment type is " . wp_get_environment_type() . " on a production site"; }
if (!$staging && !get_option("blog_public")) { $flags[] = "search engines are discouraged on a production site"; }
if (!$staging && $c("WP_DEBUG")) { $flags[] = "WP_DEBUG is on in production"; }
if (!$staging && $c("JETPACK_STAGING_MODE")) { $flags[] = "JETPACK_STAGING_MODE is on in production"; }
if ($staging && wp_get_environment_type() === "production") { $flags[] = "environment type is production on a staging site"; }

$title = ($flags ? "⚠️ " : "✅ ") . "Config report for " . $label . ($flags ? " · " . count($flags) . " issue" . (count($flags) === 1 ? "" : "s") : " · no issues");
$lines = array();
foreach ($rows as $k => $v) { $lines[] = "**" . $k . ":** " . $v; }
$body = ($flags ? "**Flags:**\n• " . implode("\n• ", $flags) . "\n\n" : "") . implode("\n", $lines);

$hook = $cfg["webhook"];
if (preg_match("#^https://(discord\\.com|discordapp\\.com)/api/webhooks/#i", $hook)) {
	$payload = array("embeds" => array(array("title" => substr($title, 0, 256), "description" => substr($body, 0, 4000), "color" => $flags ? 0xD9772C : 0x2E7D4F, "footer" => array("text" => "Wayzgoose config report · " . $label), "timestamp" => gmdate("c"))));
} elseif (preg_match("#^https://hooks\\.slack\\.com/#i", $hook)) {
	$payload = array("text" => $title, "blocks" => array(array("type" => "header", "text" => array("type" => "plain_text", "text" => substr($title, 0, 150))), array("type" => "section", "text" => array("type" => "mrkdwn", "text" => substr(str_replace("**", "*", $body), 0, 2900)))));
} else {
	$payload = array("text" => $title, "site" => home_url(), "flags" => $flags, "config" => $rows, "source" => "wayzgoose-config-report");
}
$res = wp_remote_post($hook, array("timeout" => 10, "headers" => array("Content-Type" => "application/json"), "body" => wp_json_encode($payload)));
if (is_wp_error($res)) { WP_CLI::error("Wayzgoose: webhook failed: " . $res->get_error_message()); }
WP_CLI::success("Wayzgoose: config report posted (" . count($flags) . " flags)");
