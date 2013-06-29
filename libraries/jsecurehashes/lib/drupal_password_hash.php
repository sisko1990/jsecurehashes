<?php

/**
 * @copyright Copyright (C) Drupal. All rights reserved.
 * @copyright Copyright (C) 2011 Jan Erik Zassenhaus - Joomla! Secure Password Hashes. All rights reserved.
 * @license   GNU General Public License version 2 or later; see LICENSE.txt
 */
/**
 * @file JPHANtOM
 *
 * Based on the Portable PHP password hashing framework.
 * @see http://www.openwall.com/phpass/
 *
 * An alternative or custom version of this password hashing API may be
 * used by setting the variable password_inc to the name of the PHP file
 * containing replacement user_hash_password(), user_check_password(), and
 * user_needs_new_hash() functions.
 */
// No direct access
defined('_JEXEC') or die;

/**
 * The standard log2 number of iterations for password stretching. This should
 * increase by 1 every Drupal version in order to counteract increases in the
 * speed and power of computers available to crack the hashes.
 */
define('DRUPAL_HASH_COUNT', 15);

/**
 * The minimum allowed log2 number of iterations for password stretching.
 */
define('DRUPAL_MIN_HASH_COUNT', 7);

/**
 * The maximum allowed log2 number of iterations for password stretching.
 */
define('DRUPAL_MAX_HASH_COUNT', 30);

/**
 * The expected (and maximum) number of characters in a hashed password.
 */
define('DRUPAL_HASH_LENGTH', 55);


/**
 * Returns a string for mapping an int to the corresponding base 64 character.
 */
function _password_itoa64()
{
    return './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
}


/**
 * Encode bytes into printable base 64 using the *nix standard from crypt().
 *
 * @param $input
 *   The string containing bytes to encode.
 * @param $count
 *   The number of characters (bytes) to encode.
 *
 * @return
 *   Encoded string
 */
function _password_base64_encode($input, $count)
{
    $output = '';
    $i      = 0;
    $itoa64 = _password_itoa64();
    do
    {
        $value = ord($input[$i++]);
        $output .= $itoa64[$value & 0x3f];
        if ($i < $count)
        {
            $value |= ord($input[$i]) << 8;
        }
        $output .= $itoa64[($value >> 6) & 0x3f];
        if ($i++ >= $count)
        {
            break;
        }
        if ($i < $count)
        {
            $value |= ord($input[$i]) << 16;
        }
        $output .= $itoa64[($value >> 12) & 0x3f];
        if ($i++ >= $count)
        {
            break;
        }
        $output .= $itoa64[($value >> 18) & 0x3f];
    } while ($i < $count);

    return $output;
}


/**
 * Returns a string of highly randomized bytes (over the full 8-bit range).
 *
 * This function is better than simply calling mt_rand() or any other built-in
 * PHP function because it can return a long string of bytes (compared to < 4
 * bytes normally from mt_rand()) and uses the best available pseudo-random source.
 *
 * @param $count
 *   The number of characters (bytes) to return in the string.
 */
function drupal_random_bytes($count)
{
    // $random_state does not use drupal_static as it stores random bytes.
    static $random_state, $bytes;
    // Initialize on the first call. The contents of $_SERVER includes a mix of
    // user-specific and system information that varies a little with each page.
    if (!isset($random_state))
    {
        $random_state = print_r($_SERVER, true);
        if (function_exists('getmypid'))
        {
            // Further initialize with the somewhat random PHP process ID.
            $random_state .= getmypid();
        }
        $bytes = '';
    }
    if (strlen($bytes) < $count)
    {
        // /dev/urandom is available on many *nix systems and is considered the
        // best commonly available pseudo-random source.
        if ($fh = @fopen('/dev/urandom', 'rb'))
        {
            // PHP only performs buffered reads, so in reality it will always read
            // at least 4096 bytes. Thus, it costs nothing extra to read and store
            // that much so as to speed any additional invocations.
            $bytes .= fread($fh, max(4096, $count));
            fclose($fh);
        }
        // If /dev/urandom is not available or returns no bytes, this loop will
        // generate a good set of pseudo-random bytes on any system.
        // Note that it may be important that our $random_state is passed
        // through hash() prior to being rolled into $output, that the two hash()
        // invocations are different, and that the extra input into the first one -
        // the microtime() - is prepended rather than appended. This is to avoid
        // directly leaking $random_state via the $output stream, which could
        // allow for trivial prediction of further "random" numbers.
        while (strlen($bytes) < $count)
        {
            $random_state = hash('sha256', microtime() . mt_rand() . $random_state);
            $bytes .= hash('sha256', mt_rand() . $random_state, true);
        }
    }
    $output = substr($bytes, 0, $count);
    $bytes  = substr($bytes, $count);

    return $output;
}


/**
 * Generates a random base 64-encoded salt prefixed with settings for the hash.
 *
 * Proper use of salts may defeat a number of attacks, including:
 *  - The ability to try candidate passwords against multiple hashes at once.
 *  - The ability to use pre-hashed lists of candidate passwords.
 *  - The ability to determine whether two users have the same (or different)
 *    password without actually having to guess one of the passwords.
 *
 * @param $count_log2
 *   Integer that determines the number of iterations used in the hashing
 *   process. A larger value is more secure, but takes more time to complete.
 *
 * @return
 *   A 12 character string containing the iteration count and a random salt.
 */
function _password_generate_salt($count_log2)
{
    $output = '$S$';
    // Ensure that $count_log2 is within set bounds.
    $count_log2 = _password_enforce_log2_boundaries($count_log2);
    // We encode the final log2 iteration count in base 64.
    $itoa64 = _password_itoa64();
    $output .= $itoa64[$count_log2];
    // 6 bytes is the standard salt for a portable phpass hash.
    $output .= _password_base64_encode(drupal_random_bytes(6), 6);

    return $output;
}


/**
 * Ensures that $count_log2 is within set bounds.
 *
 * @param $count_log2
 *   Integer that determines the number of iterations used in the hashing
 *   process. A larger value is more secure, but takes more time to complete.
 *
 * @return
 *   Integer within set bounds that is closest to $count_log2.
 */
function _password_enforce_log2_boundaries($count_log2)
{
    if ($count_log2 < DRUPAL_MIN_HASH_COUNT)
    {
        return DRUPAL_MIN_HASH_COUNT;
    }
    elseif ($count_log2 > DRUPAL_MAX_HASH_COUNT)
    {
        return DRUPAL_MAX_HASH_COUNT;
    }

    return (int)$count_log2;
}


/**
 * Hash a password using a secure stretched hash.
 *
 * By using a salt and repeated hashing the password is "stretched". Its
 * security is increased because it becomes much more computationally costly
 * for an attacker to try to break the hash by brute-force computation of the
 * hashes of a large number of plain-text words or strings to find a match.
 *
 * @param $algo
 *   The string name of a hashing algorithm usable by hash(), like 'sha256'.
 * @param $password
 *   The plain-text password to hash.
 * @param $setting
 *   An existing hash or the output of _password_generate_salt().  Must be
 *   at least 12 characters (the settings and salt).
 *
 * @return
 *   A string containing the hashed password (and salt) or FALSE on failure.
 *   The return string will be truncated at DRUPAL_HASH_LENGTH characters max.
 */
function _password_crypt($algo, $password, $setting)
{
    // The first 12 characters of an existing hash are its setting string.
    $setting = substr($setting, 0, 12);

    if ($setting[0] != '$' || $setting[2] != '$')
    {
        return false;
    }
    $count_log2 = _password_get_count_log2($setting);
    // Hashes may be imported from elsewhere, so we allow != DRUPAL_HASH_COUNT
    if ($count_log2 < DRUPAL_MIN_HASH_COUNT || $count_log2 > DRUPAL_MAX_HASH_COUNT)
    {
        return false;
    }
    $salt = substr($setting, 4, 8);
    // Hashes must have an 8 character salt.
    if (strlen($salt) != 8)
    {
        return false;
    }

    // Convert the base 2 logarithm into an integer.
    $count = 1 << $count_log2;

    // We rely on the hash() function being available in PHP 5.2+.
    $hash = hash($algo, $salt . $password, true);
    do
    {
        $hash = hash($algo, $hash . $password, true);
    } while (--$count);

    $len    = strlen($hash);
    $output = $setting . _password_base64_encode($hash, $len);
    // _password_base64_encode() of a 16 byte MD5 will always be 22 characters.
    // _password_base64_encode() of a 64 byte sha512 will always be 86 characters.
    $expected = 12 + ceil((8 * $len) / 6);

    return (strlen($output) == $expected) ? substr($output, 0, DRUPAL_HASH_LENGTH) : false;
}


/**
 * Parse the log2 iteration count from a stored hash or setting string.
 */
function _password_get_count_log2($setting)
{
    $itoa64 = _password_itoa64();

    return strpos($itoa64, $setting[3]);
}


/**
 * Hash a password using a secure hash.
 *
 * @param $password
 *   A plain-text password.
 * @param $count_log2
 *   Optional integer to specify the iteration count. Generally used only during
 *   mass operations where a value less than the default is needed for speed.
 *
 * @return
 *   A string containing the hashed password (and a salt), or FALSE on failure.
 */
function user_hash_password($password, $count_log2 = 0)
{
    if (empty($count_log2))
    {
        // Use the standard iteration count.
        $count_log2 = DRUPAL_HASH_COUNT;
    }

    return _password_crypt('sha512', $password, _password_generate_salt($count_log2));
}


/**
 * Check whether a plain text password matches a stored hashed password.
 *
 * Alternative implementations of this function may use other data in the
 * $account object, for example the uid to look up the hash in a custom table
 * or remote database.
 *
 * @param $password
 *   A plain-text password
 * @param $stored_hash
 *   The password hash from the database
 *
 * @return
 *   true or false
 */
function user_check_password($password, $stored_hash)
{
    // A normal Drupal 7 password using sha512.
    $hash = _password_crypt('sha512', $password, $stored_hash);

    if ($hash && $stored_hash === $hash)
    {
        return true;
    }
    else
    {
        return false;
    }
}


/**
 * Check whether a user's hashed password needs to be replaced with a new hash.
 *
 * This is typically called during the login process when the plain text
 * password is available. A new hash is needed when the desired iteration count
 * has changed through a change in the variable password_count_log2 or
 * DRUPAL_HASH_COUNT.
 *
 * @param $stored_hash
 *   The password hash from the database
 *
 * @return
 *   true or false
 */
function user_needs_new_hash($stored_hash)
{
    // Check whether this was an updated password.
    if ((substr($stored_hash, 0, 3) != '$S$') || (strlen($stored_hash) != DRUPAL_HASH_LENGTH))
    {
        return true;
    }

    // Ensure that $count_log2 is within set bounds.
    $count_log2 = _password_enforce_log2_boundaries(DRUPAL_HASH_COUNT);
    // Check whether the iteration count used differs from the standard number.
    if (_password_get_count_log2($stored_hash) !== $count_log2)
    {
        return true;
    }
    else
    {
        return false;
    }
}