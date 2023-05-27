<?php
/**
 * Plugin Name: AxelleAV
 * Description: This plugin scans your WordPress website for malware using VirusTotal.
 * Author: Johnathon M. Horner
 * Author URI: https://github.com/jhorner6511
 * License: GPL v3
 * License URI: https://www.gnu.org/licenses/gpl-3.0.en.html
 */

add_action( 'plugins_loaded', function() {

  // Get the VirusTotal API key.
  $api_key = get_option( 'virustotal_api_key' );

  // If the API key is not set, show an error message.
  if ( empty( $api_key ) ) {
    add_action( 'admin_notices', function() {
      echo '<div class="error"><p>The VirusTotal API key is not set. Please go to the <strong>Settings</strong> page and enter your API key.</p></div>';
    } );
    return;
  }

  // Create a new VirusTotal client.
  $client = new \VirusTotal\Client( $api_key );

  // Add a new action to scan the website for malware.
  add_action( 'wp_loaded', function() {

    // Get the website's URL.
    $url = home_url();

    // Scan the website for malware.
    $results = $client->scan( $url );

    // If there are any malware threats, show an error message.
    if ( ! empty( $results['threats'] ) ) {
      add_action( 'admin_notices', function() {
        echo '<div class="error"><p>Your website has been infected with malware. Please take immediate action to clean your website.</p>';
        foreach ( $results['threats'] as $threat ) {
          echo '<p><strong>' . $threat['name'] . '</strong>: ' . $threat['description'] . '</p>';
          echo '<p>IP address of the attacker: ' . $threat['ip'] . '</p>';
        }
        echo '</div>';
      } );
    } else {
      echo '<div class="success"><p>Your website is clean!</p></div>';
    }

  } );

  // Add a new setting to configure the automatic scan frequency.
  add_settings_field(
    'virustotal_scan_frequency',
    __( 'Automatic Scan Frequency' ),
    'virustotal_scan_frequency_callback',
    'reading'
  );

  // Register the setting with WordPress.
  register_setting(
    'reading',
    'virustotal_scan_frequency',
    'esc_attr'
  );

  // Add a new setting to configure the malware handling behavior.
  add_settings_field(
    'virustotal_malware_handling',
    __( 'Malware Handling' ),
    'virustotal_malware_handling_callback',
    'reading'
  );

  // Register the setting with WordPress.
  register_setting(
    'reading',
    'virustotal_malware_handling',
    'esc_attr'
  );

} );

/**
 * Callback function for the automatic scan frequency setting.
 */
function virustotal_scan_frequency_callback() {

  // Get the current scan frequency.
  $scan_frequency = get_option( 'virustotal_scan_frequency', 'hourly' );

  // Output the radio buttons.
  echo '<input type="radio" name="virustotal_scan_frequency" value="hourly" ' . checked( $scan_frequency, 'hourly', false ) . '> Hourly';
  echo '<br>';
  echo '<input type="radio" name="virustotal_scan_frequency" value="daily" ' . checked( $scan_frequency, 'daily', false ) . '> Daily';
  echo '<br>';
  echo '<input type="radio" name="virustotal_scan_frequency" value="weekly" ' . checked( $scan_frequency, 'weekly', false ) . '> Weekly';
  echo '<br>';
