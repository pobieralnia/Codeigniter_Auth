<?php if(!defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Pobieralnia	
 *
 * @package 	Pobieralnia
 * @author		Pobieralnia Dev Team
 * @copyright	Copyright (c) 2013, Pobieralnia
 * @since		Version 0.1
 */

// ------------------------------------------------------------------------

require_once APPPATH . 'libraries/member/Authorization.php';

/**
 * Pobieralnia Member
 *
 * @subpackage  Member
 * @category    Libraries
 * @author		Pobieralnia Dev Team
 * @version     0.1
 */
final class Member_library
{
    /**
     * Session user id key !!
     * @var const
     */
    const USER_ID = 'id';
    
    /**
     * CI instance
     * @var object
     */
    private $CI = NULL;
   
    // --------------------------------------------------------------------

    /**
     * Constructor 
     */
    public function __construct()
    {
        log_message('debug', "Member Class Initialized");
        
        // Get CodeIgniter instance and load necessary libraries and helpers
        $this->CI = & get_instance();
        
        // set user info into Authorization library
        Authorization\Authorization_Base::getInstance()->init(
                array(
                        'Email_Rules' => $this->CI->session->userdata('email_activated') === TRUE,
                        'Logged_Rules' => $this->CI->session->userdata(self::USER_ID) === TRUE,
                        'Unlogged_Rules' => $this->CI->session->userdata(self::USER_ID) === FALSE,
                        'Registration_Rules' => config_item('member_allow_registration')
                            ),
                array(
                        'Email_Rules' => array(
                            'err' => $this->CI->lang->line('member_email_not_activated'),
                            'err_link' => site_url(config_item('member_email_activation_link'))
                        ),
                        'Logged_Rules' => array(
                            'err' => $this->CI->lang->line('member_user_not_logged'),
                            'err_link' => site_url(config_item('member_user_not_logged_link'))
                        ),
                        'Banned_Rules' => array(
                            'err' => $this->CI->lang->line('member_user_banned'),
                            'err_link' => site_url(config_item('member_user_banned_link'))
                        ),
                        'Registration_Rules' => array(
                            'err' => $this->CI->lang->line('member_registration_disallowed'),
                            'err_link' => site_url(config_item('member_registration_closed_link'))
                        ),
                        'Unlogged_Rules' => array(
                            'err' => $this->CI->lang->line('member_user_is_logged'),
                            'err_link' => site_url(config_item('member_user_is_logged_link'))
                        ),
                )
        );
    }

    // --------------------------------------------------------------------

    /**
     * Restrict user in general we return boolean type flag
     * we can also redirect user to restricted page
     * the last option is to return array with msg and url
     * 
     * Available rules:
     *  Logged_Rules - if user is logged
     *  Banned_Rules - if user is banned
     *  Email_Rules - if user has activated email
     * 
     * Rules throw exceptions when rule is break. Please remember the correct
     * order because if we want to check if skills page is set first user must be logged (logic)
     * 
     * 
     * Example:
     * <code>
     * $this->restrict(array('Logged_Rules'), TRUE, TRUE); // We return array with errors (msg,url) if exception was thrown
     * $this->restrict(array('Logged_Rules'), TRUE, FALSE); // We return only boolean FALSE if exception was thrown
     * $this->restrict(array('Logged_Rules'), FALSE, FALSE); // We redirect user to restricted page by inoking method Member::_deny(), if exception was thrown
     * $this->restrict(array('Logged_Rules')); // The same as example above (default params)
     * $this->restrict(); // retrun boolean type TRUE
     * </code>
     * 
     * @param array $rules
     * @param boolean $return (optional) If we want to return value
     * @param boolean $return_error (optional) If we want to retun error message, it requaires $return to be TRUE
     * @return mixed
     * @see Member::_deny()
     */
    public function restrict(array $rules = array(), $return = FALSE, $return_error = FALSE)
    {
        // start
        $base = Authorization\Authorization_Base::getInstance();
        
        // reverse array to check condition from first element in array
        // design pattern decorator invoke methods from last class
        $rules = array_reverse($rules);
        
        // load rules
        foreach($rules as $val)
        {
            // check if rule is available
            if(in_array($val, Authorization\Authorization_Base::getInstance()->get_available_rules()))
            {
                try // catch unexpected exceptions from Reflection API
                {
                    // create new instance
                    $ref_object = new ReflectionClass('Authorization\\' . $val);
                    $base = $ref_object->newInstanceArgs(array($base));
                }
                catch(Exception $e)
                {
                    // alert the server admin that we have caught reflection Exception
                    log_message('error', "Member Class: restrict() method had catch reflection Exception " . $e->getMessage());
                }
            }
            else
            {
                // alert the server admin that we have caught reflection Exception
                log_message('error', "Member Class: restrict() rule doesn't exist: " . $val);
            }
        }

        $flag = FALSE;

        try
        {
            $flag = $base->authorize();
        }
        catch(Authorization\AuthLoggedException $e)
        {
            $err_url = $e->getErrorUrl();
            $err_msg = $e->getMessage();
        }
        catch(Authorization\AuthBannedException $e)
        {
            $err_url = $e->getErrorUrl();
            $err_msg = $e->getMessage();
        }
        catch(Authorization\AuthEmailException $e)
        {
            $err_url = $e->getErrorUrl();
            $err_msg = $e->getMessage();
        }
        catch(Authorization\AuthRegistrationdException $e)
        {
            $err_url = $e->getErrorUrl();
            $err_msg = $e->getMessage();
        }
        catch(Authorization\AuthUnloggedException $e)
        {
            $err_url = $e->getErrorUrl();
            $err_msg = $e->getMessage();
        }

        // deleting object instances
        if(isset($ref_object))
        {
            unset($ref_object);
        }
        unset($base);

        if($flag)
        { // no errors
            return TRUE;
        }

        // deny access we return array or flag depands on function param
        if($return)
        {
            return $return_error ? array('err_url' => $err_url, 'err_msg' => $err_msg) : FALSE;
        }

        //$this->_deny($err_msg, $err_url);
    }
}
// END Member class

/* End of file Member.php */
/* Location: ./application/libraries/member/Member.php */