<?php
/**
 * Pobieralnia
 *
 * @package 	Pobieralnia
 * @author		Pobieralnia Dev Team
 * @copyright	Copyright (c) 2013, Pobieralnia
 * @since		Version 0.1
 */

// ------------------------------------------------------------------------

/**
 * Namespace Authorization

    // Implementation
    Authorization_Base::getInstance()->init(
    array(
    'Email_Rules' => FALSE,
    'Logged_Rules' => TRUE
    ),
    array(
    'Email_Rules' => array(
    'err' => 'Nie znalazles maila',
    'err_link' => 'http://www.wp.pl'
    )
    )
    );

    $decorator = new Email_Rules( Authorization_Base::getInstance() );
    $decorator = new Logged_Rules( $decorator );

    try
    {
    $decorator->authorize();
    }
    catch (AuthLoggedException $e)
    {
    echo $e->getErrorUrl();
    echo $e->getMessage();
    }
    catch (AuthEmailException $e)
    {
    echo $e->getErrorUrl();
    echo $e->getMessage();
    }

    // Check if class exists in namespace
    if(class_exists("Authorization\\" . $val))
    {
    // get interface name
    $base_interface = class_implements(Authorization\Authorization_Base::getInstance());

    try
    {
    $ref_object = new ReflectionClass('Authorization\\' . $val);
    $ref_interface  = $ref_object->getInterfaceNames();

    // Check if classes has the same interface
    if(reset($ref_interface) == reset($base_interface))
    {
    // create new instance
    $base = $ref_object->newInstanceArgs(array($base));
    }
    }
    catch(Exception $e) {} // do nothing
    }
*/
namespace Authorization {

    /**
     * Pobieralnia AuthException
     * 
     * Main interface for Exceptions
     * 
     * @package     Pobieralnia
     * @subpackage  Authentication
     * @category    Libraries
     * @author      Pobieralnia Dev Team
     * @version     0.1
     */
    interface AuthException
    {
        /* Protected methods inherited from Exception class */

        /**
         * Get Message
         * 
         * @return string
         */
        public function getMessage();

        /**
         * Get url Error
         * 
         * @return string
         */
        public function getErrorUrl();

        /* Overrideable methods inherited from Exception class */

        /**
         * Constructor
         * 
         * @param string $message (optional)
         * @param string $url (optional)
         */
        public function __construct($message = NULL, $url = NULL);
    }

    /**
     * Pobieralnia AuthBaseException
     * 
     * Abstract class which implements methods from interface
     * We can get url Message and normal Message
     * Thats is important, because when exception is thrown we in general
     * want to redirect user (nedded url) to restricted page
     * 
     * @abstract
     */
    abstract class AuthBaseException extends \Exception implements AuthException
    {

        /**
         * Exception message
         * @var string
         * @access protected
         */
        protected $message = 'Unknown exception';

        /**
         * Exception url
         * @var string
         * @access protected
         */
        protected $url = '';

        /**
         * Constructor
         * 
         * @param string $message (optional)
         * @param string $url (optional)
         * @throws Exception
         */
        public function __construct($message = NULL, $url = NULL)
        {
            if($url)
            {
                $this->url = $url;
            }

            if(!$message)
            {
                throw new $this('Unknown exception');
            }

            parent::__construct($message);
        }

        /**
         * Get error url
         * 
         * @return string
         */
        public function getErrorUrl()
        {
            return $this->url;
        }

    }

    class AuthEmailException extends AuthBaseException{}
    class AuthLoggedException extends AuthBaseException{}
    class AuthUnloggedException extends AuthBaseException{}
    class AuthRegistrationdException extends AuthBaseException{}
    class AuthBannedException extends AuthBaseException{}
    
    /**
     * Pobieralnia Auth_Interface
     * 
     * Main interface for auth library
     * 
     * @package     Pobieralnia
     * @subpackage  Authentication
     * @category    Libraries
     * @author      Pobieralnia Dev Team
     * @version     0.1
     */
    interface Auth_Interface
    {
        public function authorize();
    }

    /**
     * Pobieralnia Authorization_Base
     * 
     * Default class for auth process, main idea
     * is that we can init this class only once ( init() ) and fill it with
     * user info because during one request user info cannot be modified.
     * Errors include message and url ( after failure user should be redirected )
     * If error message is not set there is thrown only Message.
     * 
     * Example:
     * <code>
     *   Authorization_Base::getInstance()->init(
     *      array(
     *              'Email_Rules' => FALSE,
     *              'Logged_Rules' => TRUE
     *           ),
     *      array(
     *              'Email_Rules' = array(
     *                  'err' => 'Email mistake',
     *                  'err_url' => 'http://example.com/email_wrong'
     *              )
     *          )
     *   );
     *
     * 	// Other classes - init decorators
     *  $decorator = new Email_Rules( Authorization_Base::getInstance() );
     *  $decorator = new Logged_Rules( $decorator );
     *
     * 	try   
     * 	{  
     * 		  var_dump($decorator->authorize());
     * 	}
     * 	catch (AuthEmailException $e)  
     * 	{
     * 		echo $e->getErrorUrl();  
     * 		echo $e->getMessage();
     * 	}
     *  catch (AuthLoggedException $e)  
     *  {
     * 		echo $e->getErrorUrl();  
     * 		echo $e->getMessage();
     * 	}  
     *
     * // output:
     * // Email mistake http://example.com/email_wrong
     * 
     * </code>
     * 
     * @see AuthBaseException
     */
    class Authorization_Base implements Auth_Interface
    {

        /**
         * User rules
         * @var array
         */
        private static $rules = array();

        /**
         * Errors container
         * @var array
         */
        private static $errors = array();

        /**
         * Instance of singleton class
         * @var object
         */
        private static $instance = NULL;

        /**
         * Constructor private
         * 
         * @access private
         */
        private function __construct(){}

        /**
         * Init with default values such as user info and default error
         * Only one initialization is available
         *
         * @staticvar array $rul_arr General info about user, we load this info only once
         * @param array $err_arr First error, after failure we set action/info about it
         * @return void
         * @access public
         */
        public function init(array $rul_arr, array $err_arr = array())
        {
            self::$rules = $rul_arr;

            if(!empty($err_arr))
            {
                self::$errors = $err_arr; // First error in array
            }
        }

        /**
         * Return class instance
         * 
         * @return Singleton
         * @access public
         * @static
         */
        public static function getInstance()
        {
            if(is_null(self::$instance))
            {
                self::$instance = new self();
            }
            return self::$instance;
        }

        /**
         * Check if rule is legal for user
         *
         * @return boolean
         * @access public
         */
        public function authorize()
        {
            return TRUE;
        }

        /**
         * Get errors template
         * 
         * @param string $key Error type
         * @param string $value Error value 
         * @return multiply: string, NULL
         * @access public
         * @static
         */
        public static function get_error($key, $value)
        {
            if(array_key_exists($key, self::$errors) && array_key_exists($value, self::$errors[$key]))
            {
                return self::$errors[$key][$value];
            }
            else
            {
                return NULL;
            }
        }

        /**
         * Get general info about user, his rules
         *
         * @return multiply: array, boolean
         * @access public
         * @static
         */
        public static function get_rule($key)
        {
            if(array_key_exists($key, self::$rules))
            {
                return self::$rules[$key];
            }
            else
            {
                return FALSE;
            }
        }

        /**
         * Get available rules
         * 
         * @return array
         * @static
         */
        public static function get_available_rules()
        {
            return array(
                'Email_Rules', 'Logged_Rules', 'Banned_Rules',
                'Registration_Rules', 'Unlogged_Rules'
            );
        }

        /**
         * Object to string
         * 
         * @return string
         * @access public
         */
        public function __toString()
        {
            return "Base Auth";
        }

    }
    
    /**
     * Pobieralnia Rules_Base
     * 
     * Abstract class which implements methods from interface
     * It contains all necessery methods, so decorator classes
     * (Email_Rules,Logged_Rules etc.) are symbolic
     * 
     * @abstract
     */
    abstract class Rules_Base implements Auth_Interface
    {
        /**
         * Constructor
         *
         * @param Auth_Interface $p
         * @return void
         */
        public function __construct(Auth_Interface $p)
        {
            $this->class_name = preg_replace("/" . __NAMESPACE__ . "\\\\/", "", get_class($this));
            $this->_instance = $p;
        }    
        
        /**
         * Check if rule is legal for user
         *
         * @return boolean
         */
        public function authorize()
        {
            return $this->_instance->authorize();
        }
        
        /**
         * Object to string
         * 
         * @return string
         */
        public function __toString()
        {
            return $this->class_name . " | {$this->_instance}";
        }
    }

    /**
     * Pobieralnia Email_Rules
     * 
     * Email decorator, checkin email flag
     * Main goal is to check if user activated
     * email through registration or other process
     * 
     * @see AuthEmailException
     */
    final class Email_Rules extends Rules_Base {
        
        /**
         * Check if rule is legal for user
         *
         * @return boolean
         * @throws AuthEmailException
         */
        public function authorize()
        {
            // Only when rule is correct
            if((bool) Authorization_Base::get_rule($this->class_name) === FALSE)
            {
                throw new AuthEmailException(Authorization_Base::get_error(
                        $this->class_name, "err"),
                        Authorization_Base::get_error($this->class_name, "err_link")
                        );
            }
            
            return $this->_instance->authorize() && (bool) Authorization_Base::get_rule($this->class_name);
        }
    }

    /**
     * Pobieralnia Looged_Rules
     * 
     * Logged decorator, checking logged flag
     * Main goal is to check if user is properly
     * logged
     * 
     * @see AuthLoggedException
     */
    final class Logged_Rules extends Rules_Base {
        
        /**
         * Check if rule is legal for user
         *
         * @return boolean
         * @throws AuthLoggedException
         */
        public function authorize()
        {
            // Only when rule is correct
            if((bool) Authorization_Base::get_rule($this->class_name) === FALSE)
            {
                throw new AuthLoggedException(Authorization_Base::get_error(
                        $this->class_name, "err"),
                        Authorization_Base::get_error($this->class_name, "err_link")
                        );
            }
            
            return $this->_instance->authorize() && (bool) Authorization_Base::get_rule($this->class_name);
        }
    }

    /**
     * Pobieralnia Unlooged_Rules
     * 
     * Logged decorator, checking logged flag
     * Main goal is to check if user is not
     * currently logged
     * 
     * @see AuthUnloggedException
     */
    final class Unlogged_Rules extends Rules_Base {
        
        /**
         * Check if rule is legal for user
         *
         * @return boolean
         * @throws AuthUnloggedException
         */
        public function authorize()
        {
            // Only when rule is correct
            if((bool) Authorization_Base::get_rule($this->class_name) === FALSE)
            {
                throw new AuthUnloggedException(Authorization_Base::get_error(
                        $this->class_name, "err"),
                        Authorization_Base::get_error($this->class_name, "err_link")
                        );
            }
            
            return $this->_instance->authorize() && (bool) Authorization_Base::get_rule($this->class_name);
        }
    }

    /**
     * Pobieralnia Unlooged_Rules
     * 
     * Logged decorator, checking logged flag
     * Main goal is to check if registration is
     * allowed so users can registrate
     * 
     * @see AuthRegistrationdException
     */
    final class Registration_Rules extends Rules_Base {
        
       /**
         * Check if rule is legal for user
         *
         * @return boolean
         * @throws AuthEmailException
         */
        public function authorize()
        {
            // Only when rule is correct
            if((bool) Authorization_Base::get_rule($this->class_name) === FALSE)
            {
                throw new AuthRegistrationdException(Authorization_Base::get_error(
                        $this->class_name, "err"),
                        Authorization_Base::get_error($this->class_name, "err_link")
                        );
            }
            
            return $this->_instance->authorize() && (bool) Authorization_Base::get_rule($this->class_name);
        }
    }
    
    /**
     * Pobieralnia Banned_Rules
     * 
     * Banned decorator, checking logged flag
     * Main goeal is to check if user is banned
     * 
     * @see AuthBannedException
     */
    final class Banned_Rules extends Rules_Base {
        
        /**
         * Check if rule is legal for user
         *
         * @return boolean
         * @throws AuthEmailException
         */
        public function authorize()
        {
            // Only when rule is correct
            if((bool) Authorization_Base::get_rule($this->class_name) === FALSE)
            {
                throw new AuthBannedException(Authorization_Base::get_error(
                        $this->class_name, "err"),
                        Authorization_Base::get_error($this->class_name, "err_link")
                        );
            }
            
            return $this->_instance->authorize() && (bool) Authorization_Base::get_rule($this->class_name);
        }
    }

} // END Authorization NAMESPACE