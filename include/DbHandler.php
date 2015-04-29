<?php

/**
 * Class to handle all db operations
 * This class will have CRUD methods for database tables
 *
 * @author Halley Team
 * @link URL Tutorial link
 */
class DbHandler {

    private $conn;

    function __construct() {
        require_once '/DbConnect.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }

    /* ------------- `user` table method ------------------ */

    /**
     * Creating new user
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     */
    public function createUser($email, $password) {
        require_once 'PassHash.php';

        // First check if user already existed in db
        if (!$this->isUserExists($email)) {
            // Generating password hash
            $password_hash = PassHash::hash($password);

            // Generating API key
            $api_key = $this->generateApiKey();

            $sql_query = "INSERT INTO user(email, password, api_key, status) values(?, ?, ?, ". USER_NOT_ACTIVATE. ")";

            // insert query
            if ($stmt = $this->conn->prepare($sql_query)) {
                $stmt->bind_param("sss", $email, $password_hash, $api_key);

                $result = $stmt->execute();
            } else {
                var_dump($this->conn->error);
            }

            $stmt->close();
            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        } else {
            return USER_ALREADY_EXISTED;
        }
    }

    /**
     * Activate user
     * @param String $activation_code Activation code
     */
    public function activateUser($activation_code) {
        // fetching user by activation code
        $sql_query = "SELECT user_id FROM user WHERE api_key = ? AND status = ". USER_NOT_ACTIVATE;

        $stmt = $this->conn->prepare($sql_query);

        $stmt->bind_param("s", $activation_code);

        if ($stmt->execute()) {
            $stmt->bind_result($user_id);

            $stmt->store_result();

            $stmt->fetch();
        }

        if ($stmt->num_rows > 0) {
            // Found user with the activation code
            // Now activate user

            $api_key = $this->generateApiKey();

            $sql_query = "UPDATE user SET api_key = ?, status = ". USER_ACTIVATED. " WHERE user_id = ". $user_id;

            // insert query
            if ($stmt = $this->conn->prepare($sql_query)) {
                $stmt->bind_param("s", $api_key);

                $result = $stmt->execute();
            } else {
                var_dump($user_id);
                var_dump($this->conn->error);
            }

            $stmt->close();

            return USER_ACTIVATED_SUCCESSFULLY;
        } else {
            $stmt->close();

            return USER_ACTIVATE_FAILED;
        }       
    }

    /**
     * Checking user login
     * @param String $email User login email id
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
    public function checkLogin($email, $password) {
        // fetching user by email
        $stmt = $this->conn->prepare("SELECT password, status, locked FROM user WHERE email = ?");

        $stmt->bind_param("s", $email);

        $stmt->execute();

        $stmt->bind_result($password_hash, $status, $locked);

        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password

            $stmt->fetch();

            $stmt->close();

            if ($status <= 1) {
                return USER_NOT_ACTIVATE;
            } elseif ($locked) {
                return USER_LOCKED;
            } elseif (PassHash::check_password($password_hash, $password)) {
                return LOGIN_SUCCESSFULL;
            } else {
                return WRONG_PASSWORD;
            }
        } else {
            $stmt->close();
            // user not existed with the email
            return USER_NOT_REGISTER;
        }
    }

    /**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    public function isUserExists($email) {
        $stmt = $this->conn->prepare("SELECT user_id from user WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    public function isUserExists1($user_id) {
        $stmt = $this->conn->prepare("SELECT user_id from user WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getUserByEmail($email) {
        $stmt = $this->conn->prepare("SELECT email, api_key, fullname, phone, personalID, 
                                        personalID_img, link_avatar, status, created_at, locked FROM user WHERE email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($email, $api_key, $fullname, $phone, $personalID, $personalID_img,
                                    $link_avatar, $status, $created_at, $locked);
            $stmt->fetch();
            $user = array();
            $user["email"] = $email;
            $user["api_key"] = $api_key;
            $user["fullname"] = $fullname;
            $user["phone"] = $phone;
            $user["personalID"] = $personalID;
            $user["personalID_img"] = $personalID_img;
            $user["link_avatar"] = $link_avatar;
            $user["status"] = $status;
            $user["created_at"] = $created_at;
            $user["locked"] = $locked;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getUserByUserID($user_id) {
        $stmt = $this->conn->prepare("SELECT email, api_key, fullname, phone, personalID, 
                                        personalID_img, link_avatar, status, created_at, locked FROM user WHERE user_id = ?");
        $stmt->bind_param("s", $user_id);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($email, $api_key, $fullname, $phone, $personalID, $personalID_img,
                                    $link_avatar, $status, $created_at, $locked);
            $stmt->fetch();
            $user = array();
            $user["email"] = $email;
            $user["api_key"] = $api_key;
            $user["fullname"] = $fullname;
            $user["phone"] = $phone;
            $user["personalID"] = $personalID;
            $user["personalID_img"] = $personalID_img;
            $user["link_avatar"] = $link_avatar;
            $user["status"] = $status;
            $user["created_at"] = $created_at;
            $user["locked"] = $locked;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user field by user_id
     * @param String $field User User field want to get
     * @param String $user_id User id
     */
    public function getUserByField($user_id, $field) {
        $stmt = $this->conn->prepare("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
                                        WHERE TABLE_SCHEMA = 'rs' AND TABLE_NAME = 'user'");
        if ($stmt->execute()) {
            $fields = $stmt->get_result();
        }

        $fieldIsExitInTable = false;

        while ($row = $fields->fetch_assoc()) {
                if ($row['COLUMN_NAME'] == $field) {
                    $fieldIsExitInTable = true;
                    break;
                }           
        }

        if ($fieldIsExitInTable) {
            $qry = "SELECT ".$field." FROM user WHERE user_id = ?";
            $stmt = $this->conn->prepare($qry);
            $stmt->bind_param("s", $user_id);
            if ($stmt->execute()) {
                // $user = $stmt->get_result()->fetch_assoc();
                $stmt->bind_result($field);
                $stmt->fetch();
                $stmt->close();
                return $field;
            } else {
                return NULL;
            }
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getListUser() {
        $stmt = $this->conn->prepare("SELECT user_id, email, api_key, fullname, phone, personalID, 
                                        personalID_img, link_avatar, status, created_at, locked FROM user");
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $users = $stmt->get_result();
            $stmt->close();
            return $users;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT user_id FROM user WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $stmt->bind_result($user_id);
            $stmt->fetch();
            // TODO
            // $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }
    

    /**
     * Change password
     * @param String $user_id id of user
     * @param String $password Password
     */
    public function changePassword($user_id, $password) {

        // Generating password hash
        $password_hash = PassHash::hash($password);

        $stmt = $this->conn->prepare("UPDATE user set password = ?
                                        WHERE user_id = ?");
        $stmt->bind_param("si", $password_hash, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Updating user
     * @param String $user_id id of user
     * @param String $fullname Fullname
     * @param String $phone Phone Number
     * @param String $personalID Personal Identification
     * @param String $personalID_img Personal Identification Image
     * @param String $link_avatar Link Avartar
     */
    public function updateUser($user_id, $fullname, $phone, $personalID, $personalID_img, $link_avatar) {
        require_once '/Config.php';
        $conn2 = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8", DB_USERNAME, DB_PASSWORD);
        // set the PDO error mode to exception
        $conn2->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $qry = "UPDATE user set";
        $param = array();

        if (isset($fullname)) { 
            $qry .= " fullname = :fullname,"; 
        }
        if (isset($phone)) { 
            $qry .= " phone = :phone,"; 
        }
        if (isset($personalID)) { 
            $qry .= " personalID = :personalID,"; 
        }
        if (isset($personalID_img)) { 
            $qry .= " personalID_img = :personalID_img,"; 
        }
        if (isset($link_avatar)) { 
            $qry .= " link_avatar = :link_avatar,"; 
        }

        $qry .= " status = 3 WHERE user_id = :user_id";
        

        $stmt = $conn2->prepare($qry);

        if (isset($fullname)) { 
            $stmt->bindParam(':fullname', $fullname);
        }
        if (isset($phone)) { 
            $stmt->bindParam(':phone', $phone);
        }
        if (isset($personalID)) {  
            $stmt->bindParam(':personalID', $personalID);
        }
        if (isset($personalID_img)) {  
            $stmt->bindParam(':personalID_img', $personalID_img);
        }
        if (isset($link_avatar)) { 
            $stmt->bindParam(':link_avatar', $link_avatar);
        }
        $stmt->bindParam(':user_id', $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->rowCount();
        $conn2 = null;
        return $num_affected_rows > 0;
    }

    public function updateUser1($user_id, $status, $locked) {
        $stmt = $this->conn->prepare("UPDATE user set status = ?, locked = ?
                                        WHERE user_id = ?");

        $stmt->bind_param("iii", $status, $locked, $user_id);
        $stmt->execute();

        $num_affected_rows = $stmt->affected_rows;

        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Update user field by user_id
     * @param String $field User field want to update
     * @param String $user_id User id
     */
    public function updateUserField($user_id, $field, $value) {
        $stmt = $this->conn->prepare("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
                                        WHERE TABLE_SCHEMA = 'rs' AND TABLE_NAME = 'user'");
        if ($stmt->execute()) {
            $fields = $stmt->get_result();
        }

        $fieldIsExitInTable = false;

        while ($row = $fields->fetch_assoc()) {
                if ($row['COLUMN_NAME'] == $field) {
                    $fieldIsExitInTable = true;
                    break;
                }           
        }

        if ($fieldIsExitInTable) {
            $stmt = $this->conn->prepare("UPDATE user set ".$field." = ?, status = 3 WHERE user_id = ?");
            $stmt->bind_param("si", $value, $user_id);
            $stmt->execute();

            $num_affected_rows = $stmt->affected_rows;

            $stmt->close();
            return $num_affected_rows > 0;
        } else {
            return false;
        }
    }

    /**
     * Delete user
     * @param String $user_id id of user
     */
    public function deleteUser($user_id) {
        $stmt = $this->conn->prepare("DELETE FROM user WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isLockUser($api_key) {
        $stmt = $this->conn->prepare("SELECT user_id from user WHERE api_key = ? AND locked=true");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /* ------------- `driver` table method ------------------ */

    /**
     * Creating new user
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     */
    public function createDriver($user_id, $driver_license, $driver_license_img) {
        // First check if user already existed in db
        if (!$this->isDriverExists($user_id)) {

            $sql_query = "INSERT INTO driver(user_id, driver_license, driver_license_img) values(?, ?, ?)";

            // insert query
            if ($stmt = $this->conn->prepare($sql_query)) {
                $stmt->bind_param("iss", $user_id, $driver_license==NULL?'':$driver_license, $driver_license_img==NULL?'':$driver_license_img);
                $result = $stmt->execute();
            } else {
                var_dump($this->conn->error);
            }


            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return DRIVER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return DRIVER_CREATE_FAILED;
            }
        } else {
            // User with same email already existed in the db
            return DRIVER_ALREADY_EXISTED;
        }
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getDriverByUserID($user_id) {
        $stmt = $this->conn->prepare("SELECT driver_license, driver_license_img FROM driver WHERE user_id = ?");
        $stmt->bind_param("s", $user_id);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($driver_license, $driver_license_img);
            $stmt->fetch();
            $user = array();
            $user["driver_license"] = $driver_license;
            $user["driver_license_img"] = $driver_license_img;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function isDriver($user_id) {
        $stmt = $this->conn->prepare("SELECT user_id FROM driver WHERE user_id = ?");
        $stmt->bind_param("s", $user_id);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Fetching user field by user_id
     * @param String $field User User field want to get
     * @param String $user_id User id
     */
    public function getDriverByField($user_id, $field) {
        $stmt = $this->conn->prepare("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
                                        WHERE TABLE_SCHEMA = 'rs' AND TABLE_NAME = 'driver'");
        if ($stmt->execute()) {
            $fields = $stmt->get_result();
        }

        $fieldIsExitInTable = false;

        while ($row = $fields->fetch_assoc()) {
                if ($row['COLUMN_NAME'] == $field) {
                    $fieldIsExitInTable = true;
                    break;
                }           
        }

        if ($fieldIsExitInTable) {
            $qry = "SELECT ".$field." FROM driver WHERE user_id = ?";
            $stmt = $this->conn->prepare($qry);
            $stmt->bind_param("s", $user_id);
            if ($stmt->execute()) {
                // $user = $stmt->get_result()->fetch_assoc();
                $stmt->bind_result($field);
                $stmt->fetch();
                $stmt->close();
                return $field;
            } else {
                return NULL;
            }
        } else {
            return NULL;
        }
    }

    /**
     * Updating driver
     * @param String $user_id id of user
     * @param String $driver_license Driver License
     * @param String $driver_license_img Driver License Image
     */
    public function updateDriver($user_id, $driver_license, $driver_license_img) {
        $stmt = $this->conn->prepare("UPDATE driver set driver_license = ?, driver_license_img = ?
                                        WHERE user_id = ?");

        $stmt->bind_param("ssi", $driver_license, $driver_license_img, $user_id);
        $stmt->execute();

        $num_affected_rows = $stmt->affected_rows;

        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Update driver field by user_id
     * @param String $field User field want to update
     * @param String $user_id User id
     */
    public function updateDriverField($user_id, $field, $value) {
        $stmt = $this->conn->prepare("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
                                        WHERE TABLE_SCHEMA = 'rs' AND TABLE_NAME = 'driver'");
        if ($stmt->execute()) {
            $fields = $stmt->get_result();
        }

        $fieldIsExitInTable = false;

        while ($row = $fields->fetch_assoc()) {
                if ($row['COLUMN_NAME'] == $field) {
                    $fieldIsExitInTable = true;
                    break;
                }           
        }

        if ($fieldIsExitInTable) {
            $stmt = $this->conn->prepare("UPDATE driver set ".$field." = ? WHERE user_id = ?");
            $stmt->bind_param("ss", $value, $user_id);
            $stmt->execute();

            $num_affected_rows = $stmt->affected_rows;

            $stmt->close();
            return $num_affected_rows > 0;
        } else {
            return false;
        }
    }

    /**
     * Delete driver
     * @param String $user_id id of user
     */
    public function deleteDriver($user_id) {
        $stmt = $this->conn->prepare("DELETE FROM driver WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

        /**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    private function isDriverExists($user_id) {
        $stmt = $this->conn->prepare("SELECT user_id from driver WHERE user_id = ?");
        $stmt->bind_param("s", $user_id);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /* ------------- `Vehicle` table method ------------------ */

    public function createVehicle($user_id, $type, $license_plate, $license_plate_img, $reg_certificate
                                        $vehicle_img, $motor_insurance_img) {
        // First check if user already existed in db
        if (!$this->isDriverExists($user_id)) {

            $sql_query = "INSERT INTO driver(user_id, driver_license, driver_license_img) values(?, ?, ?)";

            // insert query
            if ($stmt = $this->conn->prepare($sql_query)) {
                $stmt->bind_param("iss", $user_id, $driver_license==NULL?'':$driver_license, $driver_license_img==NULL?'':$driver_license_img);
                $result = $stmt->execute();
            } else {
                var_dump($this->conn->error);
            }


            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return VEHICLE_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return VEHICLE_CREATE_FAILED;
            }
        } else {
            // User with same email already existed in the db
            return VEHICLE_ALREADY_EXISTED;
        }
    }

    /* ------------- `staff` table method ------------------ */

    /**
     * Creating new staff
     * @param String $fullname Staff full name
     * @param String $email Staff login email id
     * @param String $personalID Staff personal ID
     */
    public function createStaff($role, $email, $fullname, $personalID) {
        require_once 'PassHash.php';

        // First check if user already existed in db
        if (!$this->isStaffExists($email)) {
            // Generating password hash
            $password_hash = PassHash::hash($email);

            // Generating API key
            $api_key = $this->generateApiKey();

            $sql_query = "INSERT INTO staff(email, password, api_key, role, fullname, personalID) 
                            values(?, ?, ?, ?, ?, ?)";

            // insert query
            if ($stmt = $this->conn->prepare($sql_query)) {
                $stmt->bind_param("sssiss", $email, $password_hash, $api_key, $role==NULL?ROLE_STAFF:$role,
                                    $fullname==NULL?' ':$fullname, $personalID==NULL?' ':$personalID);
                $result = $stmt->execute();
            } else {
                var_dump($this->conn->error);
            }

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return STAFF_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return STAFF_CREATE_FAILED;
            }
        } else {
            // User with same email already existed in the db
            return STAFF_ALREADY_EXISTED;
        }
    }

    /**
     * Checking staff login
     * @param String $email staff login email id
     * @param String $password staff login password
     * @return boolean User login status success/fail
     */
    public function checkLoginStaff($email, $password) {
        // fetching staff by email
        $stmt = $this->conn->prepare("SELECT password, role FROM staff WHERE email = ?");

        $stmt->bind_param("s", $email);

        $stmt->execute();

        $stmt->bind_result($password_hash, $role);

        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password

            $stmt->fetch();

            $stmt->close();

            if (PassHash::check_password($password_hash, $password)) {
                return LOGIN_SUCCESSFULL;
            } else {
                // staff password is incorrect
                return WRONG_PASSWORD;
            }
        } else {
            $stmt->close();
            // staff not existed with the email
            return STAFF_NOT_REGISTER;
        }
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getListStaff() {
        $stmt = $this->conn->prepare("SELECT staff_id, email, api_key, fullname, personalID, 
                                        link_avatar, created_at FROM staff");
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $staffs = $stmt->get_result();
            $stmt->close();
            return $staffs;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching staff by email
     * @param String $email Staff email id
     */
    public function getStaffByEmail($email) {
        $stmt = $this->conn->prepare("SELECT role, email, api_key, fullname, personalID, created_at, link_avatar, staff_id   
                                        FROM staff WHERE email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($role, $email, $api_key, $fullname,$personalID, $created_at, $link_avatar, $staff_id);
            $stmt->fetch();
            $staff = array();
            $staff["role"] = $role;
            $staff["email"] = $email;
            $staff["api_key"] = $api_key;
            $staff["fullname"] = $fullname;
            $staff["personalID"] = $personalID;
            $staff["created_at"] = $created_at;
            $staff["link_avatar"] = $link_avatar;
            $staff["staff_id"] = $staff_id;
            $stmt->close();
            return $staff;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching staff by staff id
     * @param String $staff_id Staff id
     */
    public function getStaffByStaffID($staff_id) {
        $stmt = $this->conn->prepare("SELECT role, email, api_key, fullname, personalID, created_at, link_avatar 
                                        FROM staff WHERE staff_id = ?");
        $stmt->bind_param("s", $staff_id);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($role, $email, $api_key, $fullname,$personalID, $created_at, $link_avatar);
            $stmt->fetch();
            $staff = array();
            $staff["role"] = $role;
            $staff["email"] = $email;
            $staff["api_key"] = $api_key;
            $staff["fullname"] = $fullname;
            $staff["personalID"] = $personalID;
            $staff["link_avatar"] = $link_avatar;
            $staff["created_at"] = $created_at;
            $stmt->close();
            return $staff;
        } else {
            return NULL;
        }
    }

    /**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    private function isStaffExists($email) {
        $stmt = $this->conn->prepare("SELECT staff_id from staff WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Fetching staff id by api key
     * @param String $api_key staff api key
     */
    public function getStaffId($api_key) {
        $stmt = $this->conn->prepare("SELECT staff_id FROM staff WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $stmt->bind_result($staff_id);
            $stmt->fetch();
            // TODO
            // $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $staff_id;
        } else {
            return NULL;
        }
    }

    public function updateStaff($staff_id, $fullname, $email, $personalID, $link_avatar) {
        require_once '/Config.php';
        $conn2 = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8", DB_USERNAME, DB_PASSWORD);
        // set the PDO error mode to exception
        $conn2->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $qry = "UPDATE staff set";
        $param = array();

        if (isset($fullname)) { 
            $qry .= " fullname = :fullname"; 
        }
        if (isset($email)) { 
            $qry .= ", email = :email"; 
        }
        if (isset($personalID)) { 
            $qry .= ", personalID = :personalID"; 
        }
        if (isset($link_avatar)) { 
            $qry .= ", link_avatar = :link_avatar"; 
        }

        $qry .= " WHERE staff_id = :staff_id"; 

        $stmt = $conn2->prepare($qry);

        if (isset($fullname)) { 
            $stmt->bindParam(':fullname', $fullname);
        }
        if (isset($email)) { 
            $stmt->bindParam(':email', $email);
        }
        if (isset($personalID)) {  
            $stmt->bindParam(':personalID', $personalID);
        }
        if (isset($link_avatar)) { 
            $stmt->bindParam(':link_avatar', $link_avatar);
        }
        $stmt->bindParam(':staff_id', $staff_id);
        $stmt->execute();
        $num_affected_rows = $stmt->rowCount();
        $conn2 = null;
        return $num_affected_rows > 0;
    }

    /**
     * Delete staff
     * @param String $staff_id id of staff
     */
    public function deleteStaff($staff_id) {
        $stmt = $this->conn->prepare("DELETE FROM staff WHERE staff_id = ?");
        $stmt->bind_param("i", $staff_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /* ------------- `itinerary` table method ------------------ */

    //not finished yet
    /**
     * Creating new itinerary
     * @param Integer $driver_id user id to whom itinerary belongs to
     * @param String $start_address, $end_address, $leave_day, $duration, $cost, $description are itinerary's properties
     */
    public function createItinerary($driver_id, $start_address, $start_address_lat,$start_address_long,
             $end_address, $end_address_lat, $end_address_long, $pick_up_address, $pick_up_address_lat, $pick_up_address_long,
             $drop_address, $drop_address_lat, $drop_address_long, $leave_date, $duration, $cost, $description, $distance, $table) {
        $q = "INSERT INTO ".$table." (driver_id, start_address, start_address_lat, start_address_long, 
            end_address, end_address_lat, end_address_long, pick_up_address, pick_up_address_lat, pick_up_address_long, 
            drop_address, drop_address_lat, drop_address_long, leave_date, duration, cost, description, distance, status) ";
                $q .= " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,". ITINERARY_STATUS_CREATED.")";
        $stmt = $this->conn->prepare($q);

        $stmt->bind_param("isddsddsddsddsidsd",
            $driver_id, $start_address, $start_address_lat, $start_address_long, 
            $end_address, $end_address_lat, $end_address_long, $pick_up_address, $pick_up_address_lat, $pick_up_address_long,
            $drop_address, $drop_address_lat, $drop_address_long, $leave_date, $duration, $cost, $description, $distance);
        
        $result = $stmt->execute();
        $stmt->close();

        if ($result) {
            $new_itinerary_id = $this->conn->insert_id;
            
            // Itinerary successfully inserted
            return $new_itinerary_id;
            
        } else {
            return NULL;
        }

        // Check for successful insertion
        if ($result) {
            // Itinerary successfully inserted
            return ITINERARY_CREATED_SUCCESSFULLY;
        } else {
            // Failed to create itinerary
            return ITINERARY_CREATE_FAILED;
        }

    }

    //not finished yet
    /**
     * Fetching single itinerary
     * @param Integer $itinerary_id id of the itinerary
     */
    public function getItinerary($itinerary_id) {
        $q = "SELECT * FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($itinerary_id, $driver_id, $customer_id, $start_address, $start_address_lat, $start_address_long,
                $pick_up_address, $pick_up_address_lat, $pick_up_address_long,
                $drop_address, $drop_address_lat, $drop_address_long,
                $end_address, $end_address_lat, $end_address_long,
                $leave_date, $duration, $distance, $cost, $description, $status, $created_at);
            // TODO
            // $task = $stmt->get_result()->fetch_assoc();
            $stmt->fetch();
            $res["itinerary_id"] = $itinerary_id;
            $res["driver_id"] = $driver_id;
            $res["customer_id"] = $customer_id;
            $res["start_address"] = $start_address;
            $res["start_address_lat"] = $start_address_lat;
            $res["start_address_long"] = $start_address_long;
            $res["pick_up_address"] = $pick_up_address;
            $res["pick_up_address_lat"] = $pick_up_address_lat;
            $res["pick_up_address_long"] = $pick_up_address_long;
            $res["drop_address"] = $drop_address;
            $res["drop_address_lat"] = $drop_address_lat;
            $res["drop_address_long"] = $drop_address_long;
            $res["end_address"] = $end_address;
            $res["end_address_lat"] = $end_address_lat;
            $res["end_address_long"] = $end_address_long;
            $res["leave_date"] = $leave_date;
            $res["duration"] = $duration;
            $res["distance"] = $distance;
            $res["cost"] = $cost;
            $res["description"] = $description;
            $res["status"] = $status;
            $res["created_at"] = $created_at;
            $stmt->close();
            return $res;
        } else {
            return NULL;
        }

    }

    //not finished yet
    /**
     * Fetching all itineraries
     */
    public function getAllItineraries() {
        $q = "SELECT * FROM itinerary";
        $stmt = $this->conn->prepare($q);
        $stmt->execute();
        $itineraries = $stmt->get_result();
        $stmt->close();
        return $itineraries;
    }

    public function getAverageRatingofDriver($driver_id){
        $q = "SELECT AVG(rating) AS average_rating FROM rating WHERE user_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$driver_id);
        $stmt->execute();

        $stmt->bind_result($average_rating);
            $stmt->close();

        if($average_rating == null){
            return 0;
        } else {
            return $average_rating;
        }
    }

    public function getAllItinerariesWithDriverInfo($user_id) {
        //$q = "SELECT * FROM itinerary, driver, user WHERE itinerary.driver_id = driver.user_id AND driver.user_id = user.user_id";
        $q = "SELECT i.itinerary_id, i.driver_id, i.customer_id, i.start_address, i.start_address_lat, i.start_address_long,
            i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, 
            i.drop_address_long, i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, 
            i.distance, i.cost, i.description, i.status as itinerary_status, i.created_at,
            d.driver_license, d.driver_license_img, u.user_id, u.email, u.fullname, u.phone, u.personalID, u.link_avatar ";
        $q .=    "FROM itinerary as i, driver as d, user as u ";
        $q .=     "WHERE i.driver_id = d.user_id AND d.user_id = u.user_id AND i.driver_id <> ? ";       

        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$user_id);
        $stmt->execute();
        $itineraries = $stmt->get_result();
        $stmt->close();

        $result = array();
        // looping through result and preparing tasks array
        while ($itinerary = $itineraries->fetch_assoc()) {
            $tmp = array();

            $tmp["itinerary_id"] = $itinerary["itinerary_id"];
            $tmp["driver_id"] = $itinerary["driver_id"];
            $tmp["customer_id"] = $itinerary["customer_id"];
            $tmp["start_address"] = $itinerary["start_address"];
            $tmp["start_address_lat"] = $itinerary["start_address_lat"];
            $tmp["start_address_long"] = $itinerary["start_address_long"];
            $tmp["pick_up_address"] = $itinerary["pick_up_address"];
            $tmp["pick_up_address_lat"] = $itinerary["pick_up_address_lat"];
            $tmp["pick_up_address_long"] = $itinerary["pick_up_address_long"];
            $tmp["drop_address"] = $itinerary["drop_address"];
            $tmp["drop_address_lat"] = $itinerary["drop_address_lat"];
            $tmp["drop_address_long"] = $itinerary["drop_address_long"];
            $tmp["end_address"] = $itinerary["end_address"];
            $tmp["end_address_lat"] = $itinerary["end_address_lat"];
            $tmp["end_address_long"] = $itinerary["end_address_long"];
            $tmp["leave_date"] = $itinerary["leave_date"];
            $tmp["duration"] = $itinerary["duration"];
            $tmp["distance"] = $itinerary["distance"];
            $tmp["cost"] = $itinerary["cost"];
            $tmp["description"] = $itinerary["description"];
            $tmp["status"] = $itinerary["itinerary_status"];
            $tmp["created_at"] = $itinerary["created_at"];

            //driver info
            $tmp["driver_license"] = $itinerary["driver_license"];
            $tmp["driver_license_img"] = $itinerary["driver_license_img"];
            
            //user info
            $tmp["user_id"] = $itinerary["user_id"];
            $tmp["email"] = $itinerary["email"];
            $tmp["fullname"] = $itinerary["fullname"];
            $tmp["phone"] = $itinerary["phone"];
            $tmp["personalID"] = $itinerary["personalID"];
            $tmp["link_avatar"] = $itinerary["link_avatar"];

            //rating
            $tmp["average_rating"] = $this->getAverageRatingofDriver($itinerary["user_id"]);
            array_push($result, $tmp);
        }

        return $result;
    }

    public function searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $user_id) {
        require_once '/Config.php';
        $conn2 = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8", DB_USERNAME, DB_PASSWORD);
        // set the PDO error mode to exception
        $conn2->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $q = "SELECT i.itinerary_id, i.driver_id, i.customer_id, i.start_address, i.start_address_lat, i.start_address_long, 
                i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, i.drop_address_long, 
                i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, i.distance, i.cost, i.description, i.status, 
                i.created_at, d.driver_license, d.driver_license_img
              FROM (SELECT * FROM itinerary WHERE status = 1 AND leave_date >='". date('m/d/Y H:i:s', time()). "' AND 
                (ABS(start_address_lat - :start_address_lat) + ABS(start_address_long - :start_address_long)) < 6 AND 
                (ABS(end_address_lat - :end_address_lat) + ABS(end_address_long - :end_address_long)) < 6) as i 
              INNER JOIN (select * from driver where user_id <> :user_id and status = 2) as d 
              ON i.driver_id = d.user_id
              WHERE ";

        $q.= "1";
                 
        $stmt = $conn2->prepare($q);

        $stmt->bindParam(':start_address_lat', $start_address_lat);
        $stmt->bindParam(':start_address_long', $start_address_long);
        $stmt->bindParam(':end_address_lat', $end_address_lat);
        $stmt->bindParam(':end_address_long', $end_address_long);
        $stmt->bindParam(':user_id', $user_id);

        // if (isset($start_address)) {
        //     $stmt->bindParam(':start_address', $start_address);
        // }
        // if (isset($end_address)) {
        //     $stmt->bindParam(':end_address', $end_address);
        // }

        $stmt->execute();
        $itineraries = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return $itineraries;
    }

    //not finished yet
    /**
     * Fetching all itineraries of one driver
     * @param Integer $driver_id id of the driver
     */
    public function getDriverItineraries($driver_id, $order) {
        $q = "SELECT itinerary_id, i.driver_id, i.customer_id, start_address, start_address_lat, start_address_long,
            pick_up_address, pick_up_address_lat, pick_up_address_long, drop_address, drop_address_lat, drop_address_long,
            end_address, end_address_lat, end_address_long, leave_date, duration, distance, cost, description, i.status as itinerary_status, i.created_at,
            driver_license, driver_license_img, u.user_id, u.email, u.fullname, u.phone, personalID, link_avatar ";
        $q .=    "FROM itinerary as i, driver as d, user as u ";
        $q .=     "WHERE i.driver_id = d.user_id AND d.user_id = u.user_id AND driver_id = ? ";

        if(isset($order)){
            $q .= "ORDER BY " .$order;
        } else {
            $q .= "ORDER BY itinerary_status";
        }
        //$q = "SELECT * FROM itinerary WHERE driver_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$driver_id);
        $stmt->execute();
        $itineraries = $stmt->get_result();
        $stmt->close();
        return $itineraries;
    }

    //not finished yet
    /**
     * Fetching all itineraries of one customer
     * @param Integer $customer_id id of the customer
     */
    public function getCustomerItineraries($customer_id, $order) {
        $q = "SELECT itinerary_id, i.driver_id, i.customer_id, start_address, start_address_lat, start_address_long,
            pick_up_address, pick_up_address_lat, pick_up_address_long, drop_address, drop_address_lat, drop_address_long,
            end_address, end_address_lat, end_address_long, leave_date, duration, distance, cost, description, i.status as itinerary_status, i.created_at,
            driver_license, driver_license_img, u.user_id, u.email, u.fullname, u.phone, personalID, link_avatar ";
        $q .=    "FROM itinerary as i, driver as d, user as u ";
        $q .=     "WHERE i.driver_id = d.user_id AND d.user_id = u.user_id AND customer_id = ? ";
        //if(isset($order)){
        //    $q .= " ORDER BY " .$order;
        //} else {
        //    $q .= " ORDER BY itinerary_status";
        //}
        
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$customer_id);
        $stmt->execute();
        $itineraries = $stmt->get_result();
        $stmt->close();
        return $itineraries;
    }

    //not finished yet
    /**
     * Updating itinerary before accept
     * @param Integer $task_id id of the task
     * @param String $task task text
     * @param String $status task status
     */
    public function updateItinerary($itinerary_id) {
        $q = "UPDATE itinerary set start_address = ?, end_address = ?, leave_day = ?, duration = ?, cost = ?, description = ? 
                WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare();
        $stmt->bind_param("sssidsi", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    //not finished yet
    /**
     * Updating itinerary
     * @param Aray $itinerary_fields properties of the itinerary
     * @param Integer $itinerary_id id of the itinerary
     */
    public function updateItinerary2($itinerary_fields, $itinerary_id) {

        $q= "UPDATE itinerary SET ";
        foreach ($itinerary_fields as $key => $value) {
            //check whether the value is numeric
            if(!is_numeric($value)){
                $q .= "{$key} = '{$value}', ";
            } else {
                $q .= "{$key} = {$value}, ";
            }
            
        }

        $q = trim(($q));

        $nq = substr($q, 0, strlen($q) - 1 );

        $nq .= " WHERE itinerary_id = {$itinerary_id} LIMIT 1";

        $stmt = $this->conn->prepare($nq);
        
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    public function checkItineraryStatus($itinerary_id){
        $q = "SELECT status FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        $stmt->execute();
        $stmt->bind_result($status);
        $stmt->store_result();

        $stmt->fetch();
        

        //print_r($status);
        $stmt->close();
        if($status == null){
            return 0;
        } else {
            return $status;
        }
    }

    /**
     * Updating accepted itinerary by customer
     * @param Aray $itinerary_fields properties of the itinerary
     * @param Integer $itinerary_id id of the itinerary
     */
    public function updateCustomerAcceptedItinerary($itinerary_id, $customer_id) {
        //ITINERARY_STATUS_CUSTOMER_ACCEPTED
        $q = "UPDATE itinerary set customer_id = ?, status = 2 
                WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("ii",$customer_id, $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Updating rejected itinerary by customer
     * @param Aray $itinerary_fields properties of the itinerary
     * @param Integer $itinerary_id id of the itinerary
     */
    public function updateCustomerRejectedItinerary($itinerary_id) {
        $q = "UPDATE itinerary set customer_id = null, status = 1 
                WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Updating accepted itinerary by driver
     * @param Aray $itinerary_fields properties of the itinerary
     * @param Integer $itinerary_id id of the itinerary
     */
    public function updateDriverAcceptedItinerary($itinerary_id) {
        $q = "UPDATE itinerary set status = 3 
                WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Updating rejected itinerary by driver
     * @param Aray $itinerary_fields properties of the itinerary
     * @param Integer $itinerary_id id of the itinerary
     */
    public function updateDrivereRectedItinerary($itinerary_id) {
        $q = "UPDATE itinerary set customer_id = null, status = 1 
                WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    //not finished yet
    /**
     * Deleting a itinerary
     * @param String $itinerary_id id of the itinerary to delete
     */
    public function deleteItinerary($itinerary_id) {
        $stmt = $this->conn->prepare("DELETE FROM itinerary WHERE itinerary_id = ?");
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /* ------------- Feedback table ------------------ */

    public function createFeedback($email, $name, $content) {
        $sql_query = "INSERT INTO feedback(email, name, content) values(?, ?, ?)";

        // insert query
        if ($stmt = $this->conn->prepare($sql_query)) {
            $stmt->bind_param("sss", $email, $name, $content);
            $result = $stmt->execute();
        } else {
            var_dump($this->conn->error);
        }

        $stmt->close();

        // Check for successful insertion
        if ($result) {
            // User successfully inserted
            return USER_CREATED_FEEDBACK_SUCCESSFULLY;
        } else {
            // Failed to create user
            return USER_CREATE_FEEDBACK_FAILED;
        }
    }

    /* ------------- Statistic ------------------ */

    //number of users created per month
    public function statisticUserBy($field) {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, COUNT(DATE_FORMAT(created_at,'%Y-%m')) as number 
                FROM user GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
        
        $stmt = $this->conn->prepare($q);
        //$stmt->bind_param("i",$customer_id);
        $stmt->execute();
        $results = $stmt->get_result();

        $stats = array();
        // looping through result and preparing tasks array
        while ($stat = $results->fetch_assoc()) {
            $tmp = array();

            $tmp["month"] = $stat["month"];
            $tmp["number"] = $stat["number"];

            array_push($stats, $tmp);
        }

        $stmt->close();
        return $stats;
    }

    //number of itineraries creted per month
    public function statisticItineraryBy($field) {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, COUNT(DATE_FORMAT(created_at,'%Y-%m')) as number 
                FROM itinerary GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
        
        $stmt = $this->conn->prepare($q);
        //$stmt->bind_param("i",$customer_id);
        $stmt->execute();
        $results = $stmt->get_result();

        $stats = array();
        // looping through result and preparing tasks array
        while ($stat = $results->fetch_assoc()) {
            $tmp = array();

            $tmp["month"] = $stat["month"];
            $tmp["number"] = $stat["number"];

            array_push($stats, $tmp);
        }

        $stmt->close();
        return $stats;
    }

    //total money come frome itineraries per month
    public function statisticMoneyBy($field) {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, SUM(cost) as total_money 
                FROM itinerary GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
        
        $stmt = $this->conn->prepare($q);
        //$stmt->bind_param("i",$customer_id);
        $stmt->execute();
        $results = $stmt->get_result();

        $stats = array();
        // looping through result and preparing tasks array
        while ($stat = $results->fetch_assoc()) {
            $tmp = array();

            $tmp["month"] = $stat["month"];
            $tmp["total_money"] = $stat["total_money"];

            array_push($stats, $tmp);
        }

        $stmt->close();
        return $stats;
    }


    //Customer staticstic 
    //number of itineraries creted per month
    public function statisticCustomerItineraryBy($field, $customer_id) {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, COUNT(DATE_FORMAT(created_at,'%Y-%m')) as number 
                FROM (SELECT * FROM itinerary WHERE customer_id = ?) as i GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
        echo $customer_id;
        $stmt = $this->conn->prepare($q);
        if ($stmt->bind_param("i",$customer_id)) {
            $stmt->execute();
        } else {
            var_dump($this->db->error);
        }

        $results = $stmt->get_result();

        $stats = array();
        // looping through result and preparing tasks array
        while ($stat = $results->fetch_assoc()) {
            $tmp = array();

            $tmp["month"] = $stat["month"];
            $tmp["number"] = $stat["number"];

            array_push($stats, $tmp);
        }

        $stmt->close();
        return $stats;
    }

    //total money come frome itineraries per month
    public function statisticCustomerMoneyBy($field, $customer_id) {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, SUM(cost) as total_money 
                FROM (SELECT * FROM itinerary WHERE customer_id = ?) as i GROUP BY DATE_FORMAT(created_at,'%Y-%m') ";
        
        $stmt = $this->conn->prepare($q);
        if ($stmt->bind_param("i",$customer_id)) {
            $stmt->execute();
        } else {
            var_dump($this->db->error);
        }
        
        $results = $stmt->get_result();

        $stats = array();
        // looping through result and preparing tasks array
        while ($stat = $results->fetch_assoc()) {
            $tmp = array();

            $tmp["month"] = $stat["month"];
            $tmp["total_money"] = $stat["total_money"];

            array_push($stats, $tmp);
        }

        $stmt->close();
        return $stats;
    }

    //Driver Staticstic
    //number of itineraries creted per month
    public function statisticDriverItineraryBy($field, $driver_id) {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, COUNT(DATE_FORMAT(created_at,'%Y-%m')) as number 
                FROM (SELECT * FROM itinerary WHERE driver_id = ?) as i GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
        
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$driver_id);
        $stmt->execute();
        $results = $stmt->get_result();

        $stats = array();
        // looping through result and preparing tasks array
        while ($stat = $results->fetch_assoc()) {
            $tmp = array();

            $tmp["month"] = $stat["month"];
            $tmp["number"] = $stat["number"];

            array_push($stats, $tmp);
        }

        $stmt->close();
        return $stats;
    }

    //total money come frome itineraries per month
    public function statisticDriverMoneyBy($field, $driver_id) {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, SUM(cost) as total_money 
                FROM (SELECT * FROM itinerary WHERE driver_id = ?) as i GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
        
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$driver_id);
        $stmt->execute();
        $results = $stmt->get_result();

        $stats = array();
        // looping through result and preparing tasks array
        while ($stat = $results->fetch_assoc()) {
            $tmp = array();

            $tmp["month"] = $stat["month"];
            $tmp["total_money"] = $stat["total_money"];

            array_push($stats, $tmp);
        }

        $stmt->close();
        return $stats;
    }

    /* ------------- Utility method ------------------ */

    /**
     * Fetching api key
     * @param String $id id primary key in table
     */
    public function getApiKeyById($id, $page) {
        $stmt = $this->conn->prepare("SELECT api_key FROM ".$page." WHERE id = ?");
        $stmt->bind_param("i", $id);
        if ($stmt->execute()) {
            // $api_key = $stmt->get_result()->fetch_assoc();
            // TODO
            $stmt->bind_result($api_key);
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }

    /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key, $page) {
        $qry = "SELECT ".$page."_id from ".$page." WHERE api_key = ?";
        $stmt = $this->conn->prepare($qry);
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }
}

?>
