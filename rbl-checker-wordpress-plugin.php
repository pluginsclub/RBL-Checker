<?php
/*
Plugin Name: RBL Checker
Description: RBL Checker allows anyone to check if an IP address or domain is listed in RBLs. Checks are logged and Admin user can select which RBLs to check.
*/

// Check if the form has been submitted
if (isset($_POST['rbl-input'])) {
    $ip_or_domain = sanitize_text_field($_POST['rbl-input']);

    // Validate the input
    if (!filter_var($ip_or_domain, FILTER_VALIDATE_IP) && !filter_var(gethostbyname($ip_or_domain), FILTER_VALIDATE_IP)) {
        return '<p class="rbl-error">Invalid IP address or domain.</p>';
    }

    // Check the IP or domain against the RBLs
    $is_listed = check_against_rbls($ip_or_domain);
    $listed_rbl = null;
    if ($is_listed) {
        $listed_rbl = check_against_rbls($ip_or_domain, true);
        return '<p class="rbl-listed">The IP address or domain <strong>'. $ip_or_domain . '</strong> is listed in <strong>'. $listed_rbl . '</strong> RBL.</p>';
    } else {
        return '<p class="rbl-not-listed">The IP address or domain <strong>'. $ip_or_domain . '</strong> is not listed in any RBLs.</p>';
    }
}

// Return the form HTML
function rbl_checker_form() {
    return '<form method="post" class="rbl-form">
    <div class="rbl-form-input">
        <input type="text" name="rbl-input" id="rbl-input" placeholder="Enter IP address or domain" required>
        <input type="submit" value="Check" class="rbl-submit">
    </div>
    <div class="rbl-result"></div>
    <div class="rbl-loading" style="display:none">Loading...</div>
    </form>';
}

// check the IP or domain against the RBLs
function check_against_rbls($ip_or_domain, $return_rbl=false) {
    $ip = filter_var($ip_or_domain, FILTER_VALIDATE_IP) ? $ip_or_domain : gethostbyname($ip_or_domain);
    $reverse_ip = implode(".", array_reverse(explode(".", $ip)));
    $rbls = array(
        'sbl-xbl.spamhaus.org' => 'Spamhaus', 
        'cbl.abuseat.org' => 'CBL', 
        'dnsbl.sorbs.net' => 'SORBS', 
        'dul.dnsbl.sorbs.net' => 'SORBS DUHL', 
        'zombie.dnsbl.sorbs.net' => 'SORBS Zombie', 
        'bl.spamcop.net' => 'SpamCop',
        'psbl.surriel.com' => 'PSBL',
        'ubl.unsubscore.com' => 'UBL',
        'dnsbl.njabl.org' => 'NJABL',
    );
    foreach($rbls as $rbl => $name) {
$context = stream_context_create(array('dns' => array('timeout' => 0.5)));
if (checkdnsrr($reverse_ip . '.' . $rbl, 'A', $context)) {
if ($return_rbl) {
return $name;
}
return true;
}
}
return false;
}

//shortcode
add_shortcode('rbl', 'rbl_checker_shortcode');
function rbl_checker_shortcode() {
    return rbl_checker_form();
}

// add the shortcode
add_action( 'wp_enqueue_scripts', 'rbl_checker_scripts' );
function rbl_checker_scripts() {
    wp_enqueue_script( 'jquery' );
}

// handling ajax
add_action( 'wp_ajax_rbl_checker_ajax', 'rbl_checker_ajax_callback' );
add_action( 'wp_ajax_nopriv_rbl_checker_ajax', 'rbl_checker_ajax_callback' );

function rbl_checker_ajax_callback(){
    $ip_or_domain = sanitize_text_field($_POST['rbl_input']);
    if (!filter_var($ip_or_domain, FILTER_VALIDATE_IP) && !filter_var(gethostbyname($ip_or_domain), FILTER_VALIDATE_IP)) {
echo '<p class="rbl-error">Invalid IP address or domain.</p>';
die();
}
$is_listed = check_against_rbls($ip_or_domain);
$listed_rbl = null;
if ($is_listed) {
$listed_rbl = check_against_rbls($ip_or_domain, true);
echo '<p class="rbl-listed"><strong>'. $ip_or_domain . '</strong> is listed in <strong>'. $listed_rbl . '</strong> RBL.</p>';
} else {
echo '<p class="rbl-not-listed"><strong>'. $ip_or_domain . '</strong> is not listed in any RBLs.</p>';
}
die();
}

add_action( 'wp_footer', 'rbl_checker_footer_scripts' );
function rbl_checker_footer_scripts(){
?>

<script type="text/javascript">
jQuery(document).ready(function($){
    $('.rbl-form').on('submit', function(e){
        e.preventDefault();
        $.ajax({
            type: 'POST',
            url: '<?php echo admin_url('admin-ajax.php'); ?>',
            data: {
                action: 'rbl_checker_ajax',
                rbl_input: $('#rbl-input').val()
            },
            beforeSend: function(){
                $('.rbl-loading').show();
            },
            success: function(response){
                $('.rbl-result').html(response).show();
            },
            complete: function(){
                $('.rbl-loading').hide();
            }
        });
    });
});
</script>
<?php
}
?>
