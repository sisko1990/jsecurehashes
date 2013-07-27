<?php
/**
 * @copyright Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @copyright Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license   GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

// Import some helpers
jimport('joomla.user.helper');


/**
 * J!Secure Hashes library: Password hashing
 *
 * @package    Joomla.Library
 * @subpackage JSecureHashes.Password.Hashing
 */
class JSecureHashesPasswordHashing
{
    /**
     * Saves the default global password hash algorithm.
     *
     * @access private
     * @var string
     */
    private $defaultHashAlgorithm = 'md5-hex';

    /**
     * Holds all possible Joomla! password hashes.
     *
     * @static
     * @access private
     * @var array
     */
    private static $availableJHashes = array('ssha', 'sha', 'crypt', 'smd5', 'md5-hex', 'aprmd5');

    /**
     * Saves a new password hash in database.
     *
     * @access private
     *
     * @param string $hash    The password hash to save in database.
     * @param int    $user_id The user_id from #_users.
     *
     * @throws Exception
     */
    private function updatePasswordHashInDatabase($hash, $user_id)
    {
        if (!empty($hash) && !empty($user_id) && is_int($user_id))
        {
            // Get a database object
            $db    = JFactory::getDbo();
            $query = $db->getQuery(true);

            $query->update($db->quoteName('#__users'));
            $query->set($db->quoteName('password') . ' = ' . $db->quote($hash));
            $query->where($db->quoteName('id') . ' = ' . $db->quote($user_id));

            $db->setQuery($query)->query();
        }
        else
        {
            throw new Exception('LIB_JSECUREHASHES_ERROR_HASH_AND_USER_EMPTY');
        }
    }


    /**
     * Sets the default hash algorithm.
     * Possible values: ssha, sha, crypt, smd5, md5-hex, aprmd5, md5-base64 or drupal
     *
     * @access public
     *
     * @param string $hashAlgorithm The hash algorithm to use as default.
     *
     * @throws Exception
     */
    public function setDefaultHashAlgorithm($hashAlgorithm)
    {
        if (in_array($hashAlgorithm, self::$availableJHashes) || $hashAlgorithm === 'drupal')
        {
            $this->defaultHashAlgorithm = $hashAlgorithm;
        }
        else
        {
            throw new Exception('LIB_JSECUREHASHES_ERROR_HASH_ALGORITHM_UNKNOWN');
        }
    }


    /**
     * This method checks if we have a valid Joomla! user password and returns the hash algorithm.
     * If it is not a Joomla! hash or the password hash comparison is wrong it will return false.
     *
     * @access public
     *
     * @param string $passwordHashAndSalt The password hash from database.
     * @param string $password            The password in plain text.
     *
     * @return string|false
     */
    public function getJoomlaPasswordHashAlgorithmForPassword($passwordHashAndSalt, $password)
    {
        // If password has ":" in it, it is a Joomla! password hash
        if ((substr($passwordHashAndSalt, 0, 3) !== '$S$') && (strpos($passwordHashAndSalt, ':') !== false))
        {
            $parts     = explode(':', $passwordHashAndSalt);
            $crypt     = $parts[0];
            $salt      = @$parts[1];
            $testcrypt = JUserHelper::getCryptedPassword($password, $salt, $this->defaultHashAlgorithm);

            if ($crypt === $testcrypt)
            {
                return $this->defaultHashAlgorithm;
            }
            else
            {
                foreach (self::$availableJHashes as $hashtype)
                {
                    $testcrypt = JUserHelper::getCryptedPassword($password, $salt, $hashtype);
                    if ($crypt === $testcrypt)
                    {
                        return $hashtype;
                    }
                }

                // No match with the available Joomla! hashes
                return false;
            }
        }
        else
        {
            // No Joomla! password hash format
            return false;
        }
    }


    /**
     * This method checks if we have a valid Drupal user password and if so returns true.
     * If it is not a Drupal hash or the password hash comparison is wrong it will return false.
     *
     * @access public
     *
     * @param string $passwordHashAndSalt The password hash from database.
     * @param string $password            The password in plain text.
     *
     * @return boolean
     */
    public function checkDrupalPasswordHashAlgorithmForPassword($passwordHashAndSalt, $password)
    {
        // Check if we have a Drupal hash
        if (substr($passwordHashAndSalt, 0, 3) === '$S$')
        {
            jimport('jsecurehashes.lib.drupal_password_hash');

            if (user_check_password($password, $passwordHashAndSalt) === true)
            {
                // Password is correct
                return true;
            }
            else
            {
                // Password is wrong
                return false;
            }
        }
        else
        {
            // No Drupal password hash format
            return false;
        }
    }


    /**
     * Generates a new hash for a password. The default hash algorithm is used for hashing.
     *
     * @access public
     *
     * @param string $passwordToHash The plain text password to generate a hash from.
     *
     * @return string
     * @throws Exception
     */
    public function getHashForPassword($passwordToHash)
    {
        if (!empty($passwordToHash))
        {
            // Trim whitespaces
            $passwordToHash = trim($passwordToHash);

            // Hash generation for Joomla! hashes
            if ($this->defaultHashAlgorithm !== 'drupal')
            {
                $salt    = JUserHelper::genRandomPassword(32);
                $crypt   = JUserHelper::getCryptedPassword($passwordToHash, $salt, $this->defaultHashAlgorithm);
                $newHash = $crypt . ':' . $salt;
            }
            else
            {
                jimport('jsecurehashes.lib.drupal_password_hash');

                $newHash = user_hash_password($passwordToHash);
            }

            return $newHash;
        }
        else
        {
            throw new Exception('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');
        }
    }


    /**
     * Check if the password is valid. If it is right it returns true otherwise false.
     * This function also updates the hash if it is not the default hash (only possible with correct $user_id parameter).
     *
     * @access public
     *
     * @param string $passwordHashAndSalt The password hash from database.
     * @param string $passwordToCheck     The password in plain text.
     * @param int    $user_id             The id from #_users to update a wrong hash.
     *
     * @throws Exception
     * @return boolean
     */
    public function checkPasswordWithStoredHash($passwordHashAndSalt, $passwordToCheck, $user_id = null)
    {
        if (!empty($passwordHashAndSalt) && !empty($passwordToCheck))
        {
            switch ($this->defaultHashAlgorithm)
            {
                // The current algorithm for all users is a Joomla! one
                case in_array($this->defaultHashAlgorithm, self::$availableJHashes):
                    if ($this->getJoomlaPasswordHashAlgorithmForPassword($passwordHashAndSalt, $passwordToCheck) !== false)
                    {
                        return true;
                    }
                    elseif ($this->checkDrupalPasswordHashAlgorithmForPassword($passwordHashAndSalt, $passwordToCheck) === true)
                    {
                        if (!is_null($user_id) && is_int($user_id))
                        {
                            // Update to Joomla! hash
                            $newHash = $this->getHashForPassword($passwordToCheck);
                            $this->updatePasswordHashInDatabase($newHash, $user_id);
                        }

                        return true;
                    }
                    else
                    {
                        throw new Exception('JGLOBAL_AUTH_INVALID_PASS');
                    }
                    break;

                // The current algorithm for all users is a Drupal one
                case 'drupal':
                    if ($this->checkDrupalPasswordHashAlgorithmForPassword($passwordHashAndSalt, $passwordToCheck) === true)
                    {
                        return true;
                    }
                    elseif ($this->getJoomlaPasswordHashAlgorithmForPassword($passwordHashAndSalt, $passwordToCheck) !== false)
                    {
                        if (!is_null($user_id) && is_int($user_id))
                        {
                            // Update to Drupal hash
                            $newHash = $this->getHashForPassword($passwordToCheck);
                            $this->updatePasswordHashInDatabase($newHash, $user_id);
                        }

                        return true;
                    }
                    else
                    {
                        throw new Exception('JGLOBAL_AUTH_INVALID_PASS');
                    }
                    break;

                default:
                    throw new Exception('JGLOBAL_AUTH_NO_USER');
                    break;
            }
        }
        else
        {
            throw new Exception('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');
        }
    }
}