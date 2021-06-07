<?php

class sspmod_cookie_Auth_Source_CookieAuth extends \SimpleSAML_Auth_Source
{

    protected $cookieName;
    protected $redisDatatype;

    public function __construct($info, &$config)
    {
        parent::__construct($info, $config);
        $this->cookieName = isset($config['cookie_name']) ? $config['cookie_name'] : 'samldata';
        $this->redisDatatype = isset($config['redis_datatype']) ? $config['redis_datatype'] : 'saml_';
    }

    public function authenticate(&$state)
    {
        // get key from cookie
        $key = $_COOKIE[$this->cookieName];
        if (!is_string($key)) {
            throw new Exception('Could not find data key');
        }

        // get user data from redis store
        $redis = new \sspmod_redis_Store_Redis();
        $data = $redis->get($this->redisDatatype, $key);
        if (!$data) {
            throw new Exception('Could not find data for key ' . $key);
        }

        // data found, consider user logged in
        $state['Attributes'] = $data;

        return $data;
    }

}
