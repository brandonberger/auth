<?php
require_once('auth.php');
class Tests extends Auth {
    public function __construct($data)
    {
        switch ($data['type']) {
            case 'register':
                $this->testRegister($data['email'], $data['password'], $data['confirm_password']);
                break;
            case 'login':
                $this->testLogin($data['email'], $data['password']);
                break;
            case 'data':
                $this->testDataCollection();
                break;
        }
    }

    public function testRegister($email, $password, $confirmPassword)
    {
        $this->registerUser($email, $password, $confirmPassword);
    }

    public function testLogin($email, $password)
    {
        $this->loginUser($email, $password);
    }

    public function testDataCollection()
    {
        echo $this->getUserAgent();
    }
}

$test = new Tests($_POST);