=== Megurio SSL Manager ===
Contributors: wapai222
Tags: ssl, letsencrypt, certificate, https, acme
Requires at least: 5.0
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 1.4.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Let's Encrypt SSL certificate manager with multi-domain SAN support. No external libraries required.

== Description ==

Megurio SSL Manager allows you to issue and manage Let's Encrypt SSL/TLS certificates directly from your WordPress admin panel.

**Features:**

* Issue SSL certificates via ACME v2 protocol (no external libraries)
* Multi-domain (SAN) certificates — up to 100 domains per certificate
* Wildcard domain support via DNS-01 challenge
* Choose HTTP-01 file verification or DNS-01 TXT record verification when creating each certificate order
* Renewals keep using the verification method selected for the original order
* Reuse pending verification challenges while they are still valid; failed validation starts a fresh challenge flow
* Clean admin workflow with a modal form for adding certificate orders
* Automatic renewal reminder when certificate expires within 30 days
* Download certificate files as a ZIP archive (fullchain, cert, chain, private key)
* Settings page for configuring the email address used for Let's Encrypt account registration
* Issued certificate data is stored in the WordPress database, not in the plugin directory

== External services ==

This plugin connects to the Let's Encrypt ACME API to register an ACME account, request certificate orders, validate domain ownership, and issue SSL/TLS certificates.

When you create or verify a certificate order, the plugin sends the configured account email address, the requested domain names, ACME challenge responses, and ACME account/order data to Let's Encrypt. Let's Encrypt may also perform HTTP or DNS validation requests for the requested domain names.

This service is provided by Internet Security Research Group (ISRG) / Let's Encrypt.

Terms of Service / Subscriber Agreement: https://letsencrypt.org/repository/

Privacy Policy: https://letsencrypt.org/privacy/

== Installation ==

1. Upload the `megurio-ssl-manager` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Go to **Megurio SSL Manager** > **Certificate Settings** and enter your email address.
4. Go to **Megurio SSL Manager** to manage and issue certificates.

== Frequently Asked Questions ==

= Does this plugin require any external libraries? =

No. The ACME v2 client is implemented using only PHP's built-in `openssl_*` functions and the WordPress HTTP API.

= What verification methods are supported? =

Both HTTP-01 (file verification) and DNS-01 (TXT record) are supported. Choose the verification method when creating the certificate order. Renewals use the same method. Wildcard domains (e.g. `*.example.com`) always require DNS-01.

= Can I reuse a verification challenge? =

Only pending challenges can be reused. If validation fails because the challenge is invalid or unreachable, the plugin clears the pending challenge so the next File Verify or DNS Verify action gets a fresh challenge from Let's Encrypt.

= How many domains can I add to one certificate? =

Up to 100 domains per certificate (Let's Encrypt limit).

= Where are the certificate files stored? =

Issued certificate data, including the private key, is stored in the WordPress database as part of this plugin's saved certificate records. The plugin generates a temporary ZIP file only when you click Download, then removes that temporary file after sending it to your browser.

= How do I renew a certificate? =

A **Renew** button appears automatically when the certificate has 30 or fewer days remaining before expiry. The renewal button uses the verification method selected when the certificate order was created.

== Changelog ==

= 1.4.1 =
* Renamed the plugin to Megurio SSL Manager
* Added external service disclosure for Let's Encrypt
* Store issued certificate data in the WordPress database instead of the plugin directory

= 1.4.0 =
* Added verification method selection when creating certificate orders
* Changed the order form to an admin modal
* Renewal actions now follow the order's selected verification method
* Reuses pending verification challenges and resets invalid validation challenges
* Added DNS-01 (TXT record) verification support
* Added wildcard domain support
* Added ZIP download for certificate files
* Added Settings page for email configuration
* Added renewal button (shown when ≤ 30 days remaining)
* Improved security: certificate folders use unpredictable names
* Replaced storage directory protection with generated `index.php` files
* Full internationalization (English and Japanese)

= 1.0.0 =
* Initial release with HTTP-01 verification and multi-domain SAN support
