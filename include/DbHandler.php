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
        $stmt = $this->conn->prepare("SELECT d.*, u.fullname FROM driver as d INNER JOIN user as u 
                                        ON u.user_id = d.user_id WHERE d.user_id = ?");
        $stmt->bind_param("s", $user_id);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($driver_id, $driver_license, $driver_license_img, $status, $created_at, $fullname);
            $stmt->fetch();
            $user = array();
            $user["driver_id"] = $driver_id;
            $user["driver_license"] = $driver_license;
            $user["driver_license_img"] = $driver_license_img;
            $user["status"] = $status;
            $user["created_at"] = $created_at;
            $user["fullname"] = $fullname;
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
     * Fetching user by email
     * @param String $email User email id
     */
    public function getListDriver() {
        $stmt = $this->conn->prepare("SELECT d.*, u.fullname FROM user as u INNER JOIN driver as d ON d.user_id = u.user_id");
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
     * Updating driver
     * @param String $user_id id of user
     * @param String $driver_license Driver License
     * @param String $driver_license_img Driver License Image
     */
    public function updateDriver($user_id, $driver_license, $driver_license_img) {
        $stmt = $this->conn->prepare("UPDATE driver set driver_license = ?, driver_license_img = ?, status = 1 
                                        WHERE user_id = ?");

        $stmt->bind_param("ssi", $driver_license, $driver_license_img, $user_id);
        $stmt->execute();

        $num_affected_rows = $stmt->affected_rows;

        $stmt->close();
        return $num_affected_rows > 0;
    }

    public function updateDriver1($user_id, $status) {
        $stmt = $this->conn->prepare("UPDATE driver set status = ? 
                                        WHERE user_id = ?");

        $stmt->bind_param("ii", $status, $user_id);
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
            $stmt = $this->conn->prepare("UPDATE driver set ".$field." = ?, status = 1 WHERE user_id = ?");
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

    public function createVehicle($user_id, $type, $license_plate, $license_plate_img, $reg_certificate,
                                        $vehicle_img, $motor_insurance_img) {
        // First check if user already existed in db
        if (!$this->isVehicleExists($license_plate)) {

            $sql_query = "INSERT INTO vehicle(user_id, type, license_plate, license_plate_img, reg_certificate,
                                        vehicle_img, motor_insurance_img, status) values(?, ?, ?, ?, ?, ?, ?, 1)";

            // insert query
            if ($stmt = $this->conn->prepare($sql_query)) {
                $stmt->bind_param("issssss", $user_id, $type==NULL?'':$type, $license_plate==NULL?'':$license_plate
                                    , $license_plate_img==NULL?'':$license_plate_img, $reg_certificate==NULL?'':$reg_certificate
                                    , $vehicle_img==NULL?'':$vehicle_img, $motor_insurance_img==NULL?'':$motor_insurance_img);
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

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getListVehicle($user_id) {
        $stmt = $this->conn->prepare("SELECT * FROM vehicle WHERE user_id = ?");

        $stmt->bind_param("i", $user_id);

        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $vehicle = $stmt->get_result();
            $stmt->close();
            return $vehicle;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getListVehicles() {
        $stmt = $this->conn->prepare("SELECT * FROM vehicle");

        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $vehicle = $stmt->get_result();
            $stmt->close();
            return $vehicle;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getVehicle($vehicle_id) {
        $stmt = $this->conn->prepare("SELECT vehicle_id, user_id, type, license_plate, reg_certificate,
                                        license_plate_img, vehicle_img, motor_insurance_img, status, created_at
                                      FROM vehicle WHERE vehicle_id = ?");

        $stmt->bind_param("i", $vehicle_id);

        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($vehicle_id, $user_id, $type, $license_plate, $reg_certificate, $license_plate_img, $vehicle_img, $motor_insurance_img, $status, $created_at);
            $stmt->fetch();
            $vehicle = array();
            $vehicle["vehicle_id"] = $vehicle_id;
            $vehicle["user_id"] = $user_id;
            $vehicle["type"] = $type;
            $vehicle["license_plate"] = $license_plate;
            $vehicle["reg_certificate"] = $reg_certificate;
            $vehicle["license_plate_img"] = $license_plate_img;
            $vehicle["vehicle_img"] = $vehicle_img;
            $vehicle["motor_insurance_img"] = $motor_insurance_img;
            $vehicle["status"] = $status;
            $vehicle["created_at"] = $created_at;
            $stmt->close();
            return $vehicle;
        } else {
            return NULL;
        }
    }

    public function updateVehicle($vehicle_id, $type, $license_plate, $reg_certificate, $license_plate_img, $vehicle_img, $motor_insurance_img) {
        require_once '/Config.php';
        $conn2 = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8", DB_USERNAME, DB_PASSWORD);
        // set the PDO error mode to exception
        $conn2->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $qry = "UPDATE vehicle set";
        $param = array();

        if (isset($type)) { 
            $qry .= " type = :type,"; 
        }
        if (isset($license_plate)) { 
            $qry .= " license_plate = :license_plate,"; 
        }
        if (isset($reg_certificate)) { 
            $qry .= " reg_certificate = :reg_certificate,"; 
        }
        if (isset($license_plate_img)) { 
            $qry .= " license_plate_img = :license_plate_img,"; 
        }
        if (isset($vehicle_img)) { 
            $qry .= " vehicle_img = :vehicle_img,"; 
        }
        if (isset($motor_insurance_img)) { 
            $qry .= " motor_insurance_img = :motor_insurance_img,"; 
        }

        $qry .= " status = 1 WHERE vehicle_id = :vehicle_id";

        $stmt = $conn2->prepare($qry);

        if (isset($type)) { 
            $stmt->bindParam(':type', $type);
        }
        if (isset($license_plate)) { 
            $stmt->bindParam(':license_plate', $license_plate);
        }
        if (isset($reg_certificate)) {  
            $stmt->bindParam(':reg_certificate', $reg_certificate);
        }
        if (isset($license_plate_img)) {  
            $stmt->bindParam(':license_plate_img', $license_plate_img);
        }
        if (isset($vehicle_img)) { 
            $stmt->bindParam(':vehicle_img', $vehicle_img);
        }
        if (isset($motor_insurance_img)) { 
            $stmt->bindParam(':motor_insurance_img', $motor_insurance_img);
        }

        $stmt->bindParam(':vehicle_id', $vehicle_id);
        $stmt->execute();
        $num_affected_rows = $stmt->rowCount();
        $conn2 = null;
        return $num_affected_rows > 0;
    }

    public function updateVehicle1($vehicle_id, $status) {
        $stmt = $this->conn->prepare("UPDATE vehicle set status = ? 
                                        WHERE vehicle_id = ?");

        $stmt->bind_param("ii", $status, $vehicle_id);
        $stmt->execute();

        $num_affected_rows = $stmt->affected_rows;

        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Delete driver
     * @param String $user_id id of user
     */
    public function deleteVehicle($vehicle_id) {
        $stmt = $this->conn->prepare("DELETE FROM vehicle WHERE vehicle_id = ?");
        $stmt->bind_param("i", $vehicle_id);
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
    private function isVehicleExists($license_plate) {
        $stmt = $this->conn->prepare("SELECT vehicle_id FROM vehicle WHERE license_plate = ?");
        $stmt->bind_param("s", $license_plate);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /* ------------- `staff` table method ------------------ */

    /**
     * Creating new staff
     * @param String $fullname Staff full name
     * @param String $email Staff login email id
     * @param String $personalID Staff personal ID
     */
    public function createStaff($role, $email, $fullname, $personalID, $link_avatar) {
        require_once 'PassHash.php';

        // First check if user already existed in db
        if (!$this->isStaffExists($email)) {
            // Generating password hash
            $password_hash = PassHash::hash($email);

            // Generating API key
            $api_key = $this->generateApiKey();

            $sql_query = "INSERT INTO staff(email, password, api_key, role, fullname, personalID, link_avatar) 
                            values(?, ?, ?, ?, ?, ?, ?)";

            // insert query
            if ($stmt = $this->conn->prepare($sql_query)) {
                $stmt->bind_param("sssisss", $email, $password_hash, $api_key, $role==NULL?ROLE_STAFF:$role,
                                    $fullname==NULL?' ':$fullname, $personalID==NULL?' ':$personalID, $link_avatar==NULL?' ':$link_avatar);
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
             $drop_address, $drop_address_lat, $drop_address_long, $leave_date, $duration, $cost, $description, $distance, $vehicle_id, $table) {

        $name_table = split("_", $table);
        $name_table = $name_table[2];
        $q = "INSERT INTO itinerary (table_name, driver_id, vehicle_id) VALUES ('".$name_table."', ?, ?)";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param('ii', $driver_id, $vehicle_id);
        $result = $stmt->execute();
        $new_itinerary_id = $this->conn->insert_id;

        $q = "INSERT INTO ".$table." (itinerary_id, start_address, start_address_lat, start_address_long, 
            end_address, end_address_lat, end_address_long, pick_up_address, pick_up_address_lat, pick_up_address_long, 
            drop_address, drop_address_lat, drop_address_long, leave_date, duration, cost, description, distance) ";
                $q .= " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        $stmt = $this->conn->prepare($q);

        $stmt->bind_param("isddsddsddsddsidsd",
            $new_itinerary_id, $start_address, $start_address_lat, $start_address_long, 
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
        $q = "SELECT i.*, v.type as vehicle_type, u.fullname as d_fullname, u.phone FROM itinerary as i 
                INNER JOIN vehicle as v ON i.vehicle_id = v.vehicle_id
                INNER JOIN user as u on u.user_id = i.driver_id
                WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        $customer_id = "";
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($itinerary_id, $driver_id, $vehicle_id, $customer_id, $table_name, $status, $created_at, $type, $fullname, $phone);

            // TODO
            // $task = $stmt->get_result()->fetch_assoc();
            $stmt->fetch();
            $res["itinerary_id"] = $itinerary_id;
            $res["driver_id"] = $driver_id;
            $res["fullname"] = $fullname;
            $res["phone"] = $phone;
            $res["vehicle_id"] = $vehicle_id;
            $res["vehicle_type"] = $type;
            $res["customer_id"] = $customer_id;
            $res["created_at"] = $created_at;
            $res["status"] = $status;

            switch ($status) {
                case '1':
                    $table_name = 'itinerary_created_'.$table_name;
                    break;
                case '2':
                    $table_name = 'itinerary_joinning';
                    break;
                case '3':
                    $table_name = 'itinerary_accepted';
                    break;
                case '4':
                    $table_name = 'itinerary_completed';
                    break;
                default:
                    return NULL;
                    break;
            }
            
            $stmt->close();
        } else {
            return NULL;
        }

        //Right here
        $q = "SELECT fullname FROM user WHERE user_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $customer_id);

        if ($stmt->execute()) {
            $stmt->bind_result($fullname);

            // TODO
            // $task = $stmt->get_result()->fetch_assoc();
            $stmt->fetch();
            $res["customer_fullname"] = $fullname;

            $stmt->close();
        }
        //

        $q = "SELECT * FROM ".$table_name." WHERE itinerary_id = ?";

        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);

        if ($stmt->execute()) {
            $stmt->bind_result($itinerary_id, $start_address, $start_address_lat, $start_address_long,
                $pick_up_address, $pick_up_address_lat, $pick_up_address_long,
                $drop_address, $drop_address_lat, $drop_address_long,
                $end_address, $end_address_lat, $end_address_long,
                $leave_date, $duration, $distance, $cost, $description);

            // TODO
            // $task = $stmt->get_result()->fetch_assoc();
            $stmt->fetch();
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

            $stmt->close();

            $res["average_rating"] = $this->getAverageRatingofUser($res["driver_id"]);

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

    

    public function getAllItinerariesWithDriverInfo($user_id) {
        //$q = "SELECT * FROM itinerary, driver, user WHERE itinerary.driver_id = driver.user_id AND driver.user_id = user.user_id";
        $q = "SELECT i.itinerary_id, ii.driver_id, v.vehicle_id, v.type as vehicle_type, ii.customer_id, i.start_address, i.start_address_lat, i.start_address_long,
            i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, 
            i.drop_address_long, i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, 
            i.distance, i.cost, i.description, ii.status as itinerary_status, ii.created_at,
            d.driver_license, d.driver_license_img, u.user_id, u.email, u.fullname, u.phone, u.personalID, u.link_avatar ";
        $q .=    "FROM (SELECT * FROM itinerary_created_northeast
                    UNION
                    SELECT * FROM itinerary_created_northwest
                    UNION
                    SELECT * FROM itinerary_created_southeast 
                    UNION
                    SELECT * FROM itinerary_created_southwest 
                    UNION
                    SELECT * FROM itinerary_created_east 
                    UNION
                    SELECT * FROM itinerary_created_west
                    UNION
                    SELECT * FROM itinerary_created_north 
                    UNION
                    SELECT * FROM itinerary_created_south) as i, itinerary as ii, driver as d, user as u, vehicle as v ";
        $q .=     "WHERE ii.driver_id = d.user_id AND d.user_id = u.user_id AND ii.itinerary_id = i.itinerary_id AND ii.vehicle_id = v.vehicle_id";       

        $stmt = $this->conn->prepare($q);
        $stmt->execute();
        $itineraries = $stmt->get_result();
        $stmt->close();

        $result = array();
        // looping through result and preparing tasks array
        while ($itinerary = $itineraries->fetch_assoc()) {
            $tmp = array();

            $tmp["itinerary_id"] = $itinerary["itinerary_id"];
            $tmp["driver_id"] = $itinerary["driver_id"];
            $tmp["vehicle_id"] = $itinerary["vehicle_id"];
            $tmp["vehicle_type"] = $itinerary["vehicle_type"];
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
            
            $tmp["fullname"] = $itinerary["fullname"];
            $tmp["email"] = $itinerary["email"];
            $tmp["phone"] = $itinerary["phone"];
            $tmp["link_avatar"] = $itinerary["link_avatar"];

            //rating
            $tmp["average_rating"] = round($this->getAverageRatingofUser($itinerary["user_id"]), 2);
            array_push($result, $tmp);
        }

        return $result;
    }

    public function searchItineraries2($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow) {
        $text = $start_address_lat."/".$start_address_long."/".$end_address_lat."/".$end_address_long."/".$leave_date."/".$cost."/".$duration."/".$distance."/".$table;
        
        $handle = fopen("log.txt", "a");
        fwrite($handle, $text);
        fwrite($handle, "\r\n");
        fclose($handle);

        require_once '/Config.php';
        $conn2 = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8", DB_USERNAME, DB_PASSWORD);
        // set the PDO error mode to exception
        $conn2->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        if (!isset($leave_date) || $leave_date == '') {
            $leave_date = date('m/d/Y H:i:s', time());
        }

        $q = "";

        if ($table == "itinerary_created_northeast" || $table == "itinerary_created_northwest" ||
            $table == "itinerary_created_north") {
            $q .= "SELECT i.itinerary_id, ii.driver_id, r.average_rating, v.type as vehicle_type, ii.customer_id, i.start_address, i.start_address_lat, i.start_address_long, 
                i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, i.drop_address_long, 
                i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, i.distance, i.cost, i.description, ii.status, 
                ii.created_at, u.fullname, u.phone, u.link_avatar
              FROM (SELECT * FROM i_itinerary_northeastwest WHERE leave_date >='". $leave_date. "' AND 
                    (ABS(start_address_lat - :start_address_lat) < 0.05 AND ABS(start_address_long - :start_address_long) < 0.05 AND (end_address_lat - :end_address_lat) > 0.05)
                    OR (ABS(end_address_lat - :end_address_lat) < 0.05 AND ABS(end_address_long - :end_address_long) < 0.05 AND (:start_address_lat - start_address_lat) > 0.05)";
        } else if ($table == "itinerary_created_east") {
            $q .= "SELECT i.itinerary_id, ii.driver_id, r.average_rating, v.type as vehicle_type, ii.customer_id, i.start_address, i.start_address_lat, i.start_address_long, 
                i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, i.drop_address_long, 
                i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, i.distance, i.cost, i.description, ii.status, 
                ii.created_at, u.fullname, u.phone, u.link_avatar
              FROM (SELECT * FROM i_itinerary_created_eastnorthsouth WHERE leave_date >='". $leave_date. "' AND 
                    (ABS(start_address_lat - :start_address_lat) < 0.05 AND ABS(start_address_long - :start_address_long) < 0.05 AND (end_address_long - :end_address_long) > 0.05)
                    OR (ABS(end_address_lat - :end_address_lat) < 0.05 AND ABS(end_address_long - :end_address_long) < 0.05 AND (:start_address_long - start_address_long) > 0.05)";
        } else if ($table == "itinerary_created_southeast" || $table == "itinerary_created_southwest" || 
            $table == "itinerary_created_south" ) {
            $q .= "SELECT i.itinerary_id, ii.driver_id, r.average_rating, v.type as vehicle_type, ii.customer_id, i.start_address, i.start_address_lat, i.start_address_long, 
                i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, i.drop_address_long, 
                i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, i.distance, i.cost, i.description, ii.status, 
                ii.created_at, u.fullname, u.phone, u.link_avatar
              FROM (SELECT * FROM i_itinerary_southeastwest WHERE leave_date >='". $leave_date. "' AND 
                    (ABS(start_address_lat - :start_address_lat) < 0.05 AND ABS(start_address_long - :start_address_long) < 0.05 AND (:end_address_lat - end_address_lat) > 0.05)
                    OR (ABS(end_address_lat - :end_address_lat) < 0.05 AND ABS(end_address_long - :end_address_long) < 0.05 AND (start_address_lat - :start_address_lat) > 0.05)";
        } else {
            $q .= "SELECT i.itinerary_id, ii.driver_id, r.average_rating, v.type as vehicle_type, ii.customer_id, i.start_address, i.start_address_lat, i.start_address_long, 
                i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, i.drop_address_long, 
                i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, i.distance, i.cost, i.description, ii.status, 
                ii.created_at, u.fullname, u.phone, u.link_avatar
              FROM (SELECT * FROM i_itinerary_created_westnorthsouth WHERE leave_date >='". $leave_date. "' AND 
                    (ABS(start_address_lat - :start_address_lat) < 0.05 AND ABS(start_address_long - :start_address_long) < 0.05 AND (:end_address_long - end_address_long) > 0.05)
                    OR (ABS(end_address_lat - :end_address_lat) < 0.05 AND ABS(end_address_long - :end_address_long) < 0.05 AND (start_address_long - :start_address_long) > 0.05)"; 
        }

        if (isset($duration) && $duration != '') {
            $q .= " AND duration <= :duration";
        }
        if (isset($cost) && $cost != '') {
            $q .= " AND cost <= :cost";
        }
        if (isset($distance) && $distance != '') {
            $q .= " AND distance <= :distance";
        }

        $q .= ") as i 
              INNER JOIN (select * from itinerary where status = 1) as ii
              ON ii.itinerary_id = i.itinerary_id
              INNER JOIN (select * from driver where user_id <> :user_id and status = 2) as d 
              ON ii.driver_id = d.user_id
              INNER JOIN (SELECT * from user where locked <> 1 and status = 4) as u 
              ON d.user_id = u.user_id
              INNER JOIN vehicle  as v
              ON v.vehicle_id = ii.vehicle_id
              INNER JOIN (SELECT rating_user_id, ROUND(AVG(rating),2) as average_rating FROM rating GROUP BY rating_user_id) as r
              ON r.rating_user_id = d.user_id
              ORDER BY i.cost ASC, r.average_rating DESC, i.distance ASC, i.duration ASC";

        if (isset($startRow) && isset($endRow)) {
            $q .= " LIMIT ".$startRow.", ".$endRow;
        }
                 
        $stmt = $conn2->prepare($q);

        if (isset($duration) && $duration != '') {
            $stmt->bindParam(':duration', $duration);
        }
        if (isset($cost) && $cost != '') {
            $stmt->bindParam(':cost', $cost);
        }
        if (isset($distance) && $distance != '') {
            $stmt->bindParam(':distance', $distance);
        }

        if ($table == "AllStart") {
            $stmt->bindParam(':start_address_lat', $start_address_lat);
            $stmt->bindParam(':start_address_long', $start_address_long);
        } else if ($table == "AllEnd") {
            $stmt->bindParam(':end_address_lat', $end_address_lat);
            $stmt->bindParam(':end_address_long', $end_address_long);
        } else {
            $stmt->bindParam(':start_address_lat', $start_address_lat);
            $stmt->bindParam(':start_address_long', $start_address_long);
            $stmt->bindParam(':end_address_lat', $end_address_lat);
            $stmt->bindParam(':end_address_long', $end_address_long);
        }
        
        $stmt->bindParam(':user_id', $user_id);

        $stmt->execute();
        $itineraries = $stmt->fetchAll(PDO::FETCH_ASSOC);

        //print_r($itineraries);

        return $itineraries;
    }

    public function searchItineraries($start_address_lat, $start_address_long, $end_address_lat, $end_address_long, $leave_date, $duration, $cost, $distance, $user_id, $table, $startRow, $endRow) {
        $text = $start_address_lat."/".$start_address_long."/".$end_address_lat."/".$end_address_long."/".$leave_date."/".$cost."/".$duration."/".$distance."/".$table;
        
        $handle = fopen("log.txt", "a");
        fwrite($handle, $text);
        fwrite($handle, "\r\n");
        fclose($handle);

        require_once '/Config.php';
        $conn2 = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8", DB_USERNAME, DB_PASSWORD);
        // set the PDO error mode to exception
        $conn2->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        if (!isset($leave_date) || $leave_date == '') {
            $leave_date = date('m/d/Y H:i:s', time());
        }

        $q = "";

        if ($table == "itinerary_created_northeast" || $table == "itinerary_created_northwest" ||
            $table == "itinerary_created_north" || $table == "itinerary_created_east" ||
            $table == "itinerary_created_southeast" || $table == "itinerary_created_southwest" ||
            $table == "itinerary_created_south" || $table == "itinerary_created_west") {
            $q .= "SELECT i.itinerary_id, ii.driver_id, r.average_rating, v.type as vehicle_type, ii.customer_id, i.start_address, i.start_address_lat, i.start_address_long, 
                i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, i.drop_address_long, 
                i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, i.distance, i.cost, i.description, ii.status, 
                ii.created_at, u.fullname, u.phone, u.link_avatar
              FROM (SELECT * FROM ".$table." WHERE leave_date >='". $leave_date. "' AND (ABS(start_address_lat - :start_address_lat) < 0.05)
                    AND (ABS(start_address_long - :start_address_long) < 0.05)
                    AND (ABS(:end_address_lat - end_address_lat) < 0.05)
                    AND (ABS(:end_address_long - end_address_long) < 0.05)";
        } else if ($table == "AllStart") {
            $q .= "SELECT i.itinerary_id, ii.driver_id, r.average_rating, v.type as vehicle_type, ii.customer_id, i.start_address, i.start_address_lat, i.start_address_long, 
                i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, i.drop_address_long, 
                i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, i.distance, i.cost, i.description, ii.status, 
                ii.created_at, u.fullname, u.phone, u.link_avatar
              FROM (SELECT * FROM itinerary_created_northeast WHERE leave_date >='". $leave_date. "' AND 
                    ABS(start_address_lat - :start_address_lat) < 0.2 AND ABS(start_address_long - :start_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_northwest WHERE leave_date >='". $leave_date. "' AND 
                    ABS(start_address_lat - :start_address_lat) < 0.2 AND ABS(start_address_long - :start_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_southeast WHERE leave_date >='". $leave_date. "' AND 
                    ABS(start_address_lat - :start_address_lat) < 0.2 AND ABS(start_address_long - :start_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_southwest WHERE leave_date >='". $leave_date. "' AND 
                    ABS(start_address_lat - :start_address_lat) < 0.2 AND ABS(start_address_long - :start_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_east WHERE leave_date >='". $leave_date. "' AND 
                    ABS(start_address_lat - :start_address_lat) < 0.2 AND ABS(start_address_long - :start_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_west WHERE leave_date >='". $leave_date. "' AND 
                    ABS(start_address_lat - :start_address_lat) < 0.2 AND ABS(start_address_long - :start_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_north WHERE leave_date >='". $leave_date. "' AND 
                    ABS(start_address_lat - :start_address_lat) < 0.2 AND ABS(start_address_long - :start_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_south WHERE leave_date >='". $leave_date. "' AND 
                    ABS(start_address_lat - :start_address_lat) < 0.2 AND ABS(start_address_long - :start_address_long) < 0.2";
        } else if ($table == "AllEnd") {
            $q .= "SELECT i.itinerary_id, ii.driver_id, r.average_rating, v.type as vehicle_type, ii.customer_id, i.start_address, i.start_address_lat, i.start_address_long, 
                i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, i.drop_address_long, 
                i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, i.distance, i.cost, i.description, ii.status, 
                ii.created_at, u.fullname, u.phone, u.link_avatar
              FROM (SELECT * FROM itinerary_created_northeast WHERE leave_date >='". $leave_date. "' AND 
                    ABS(end_address_lat - :end_address_lat) < 0.2 AND ABS(end_address_long - :end_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_northwest WHERE leave_date >='". $leave_date. "' AND 
                    ABS(end_address_lat - :end_address_lat) < 0.2 AND ABS(end_address_long - :end_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_southeast WHERE leave_date >='". $leave_date. "' AND 
                    ABS(end_address_lat - :end_address_lat) < 0.2 AND ABS(end_address_long - :end_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_southwest WHERE leave_date >='". $leave_date. "' AND 
                    ABS(end_address_lat - :end_address_lat) < 0.2 AND ABS(end_address_long - :end_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_east WHERE leave_date >='". $leave_date. "' AND 
                    ABS(end_address_lat - :end_address_lat) < 0.2 AND ABS(end_address_long - :end_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_west WHERE leave_date >='". $leave_date. "' AND 
                    ABS(end_address_lat - :end_address_lat) < 0.2 AND ABS(end_address_long - :end_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_north WHERE leave_date >='". $leave_date. "' AND 
                    ABS(end_address_lat - :end_address_lat) < 0.2 AND ABS(end_address_long - :end_address_long) < 0.2
                    UNION
                    SELECT * FROM itinerary_created_south WHERE leave_date >='". $leave_date. "' AND 
                    ABS(end_address_lat - :end_address_lat) < 0.2 AND ABS(end_address_long - :end_address_long) < 0.2";
        } else {
            $q .= "SELECT i.itinerary_id, ii.driver_id, r.average_rating, v.type as vehicle_type, ii.customer_id, i.start_address, i.start_address_lat, i.start_address_long, 
                i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, i.drop_address_long, 
                i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, i.distance, i.cost, i.description, ii.status, 
                ii.created_at, u.fullname, u.phone, u.link_avatar
              FROM (SELECT * FROM itinerary_created_northeast
                    UNION
                    SELECT * FROM itinerary_created_northwest
                    UNION
                    SELECT * FROM itinerary_created_southeast 
                    UNION
                    SELECT * FROM itinerary_created_southwest 
                    UNION
                    SELECT * FROM itinerary_created_east 
                    UNION
                    SELECT * FROM itinerary_created_west
                    UNION
                    SELECT * FROM itinerary_created_north 
                    UNION
                    SELECT * FROM itinerary_created_south";
        }

        if (isset($duration) && $duration != '') {
            $q .= " AND duration <= :duration";
        }
        if (isset($cost) && $cost != '') {
            $q .= " AND cost <= :cost";
        }
        if (isset($distance) && $distance != '') {
            $q .= " AND distance <= :distance";
        }

        $q .= ") as i 
              INNER JOIN (select * from itinerary where status = 1) as ii
              ON ii.itinerary_id = i.itinerary_id
              INNER JOIN (select * from driver where user_id <> :user_id and status = 2) as d 
              ON ii.driver_id = d.user_id
              INNER JOIN (SELECT * from user where locked <> 1 and status = 4) as u 
              ON d.user_id = u.user_id
              INNER JOIN vehicle  as v
              ON v.vehicle_id = ii.vehicle_id
              INNER JOIN (SELECT rating_user_id, ROUND(AVG(rating),2) as average_rating FROM rating GROUP BY rating_user_id) as r
              ON r.rating_user_id = d.user_id
              ORDER BY i.cost ASC, r.average_rating DESC, i.distance ASC, i.duration ASC";

        if (isset($startRow) && isset($endRow)) {
            $q .= " LIMIT ".$startRow.", ".$endRow;
        }
                 
        $stmt = $conn2->prepare($q);

        if (isset($duration) && $duration != '') {
            $stmt->bindParam(':duration', $duration);
        }
        if (isset($cost) && $cost != '') {
            $stmt->bindParam(':cost', $cost);
        }
        if (isset($distance) && $distance != '') {
            $stmt->bindParam(':distance', $distance);
        }

        if ($table == "AllStart") {
            $stmt->bindParam(':start_address_lat', $start_address_lat);
            $stmt->bindParam(':start_address_long', $start_address_long);
        } else if ($table == "AllEnd") {
            $stmt->bindParam(':end_address_lat', $end_address_lat);
            $stmt->bindParam(':end_address_long', $end_address_long);
        } else {
            $stmt->bindParam(':start_address_lat', $start_address_lat);
            $stmt->bindParam(':start_address_long', $start_address_long);
            $stmt->bindParam(':end_address_lat', $end_address_lat);
            $stmt->bindParam(':end_address_long', $end_address_long);
        }
        
        $stmt->bindParam(':user_id', $user_id);

        $stmt->execute();
        $itineraries = $stmt->fetchAll(PDO::FETCH_ASSOC);

        //print_r($itineraries);

        return $itineraries;
    }
    //not finished yet
    /**
     * Fetching all itineraries of one driver
     * @param Integer $driver_id id of the driver
     */
    public function getDriverItineraries($driver_id, $order) {
        $q = "SELECT i.itinerary_id, i.driver_id, r.average_rating, i.vehicle_id, v.type as vehicle_type, i.customer_id, i.start_address, i.start_address_lat, i.start_address_long,
            i.pick_up_address, i.pick_up_address_lat, i.pick_up_address_long, i.drop_address, i.drop_address_lat, i.drop_address_long,
            i.end_address, i.end_address_lat, i.end_address_long, i.leave_date, i.duration, i.distance, i.cost, i.description, i.status as itinerary_status, i.created_at,
            d.driver_license, d.driver_license_img, u.user_id, u.email, u.fullname, u.phone, u.personalID, u.link_avatar ";
        $q .=    "FROM i_itinerary as i
                    INNER JOIN driver as d 
                    ON i.driver_id = d.user_id
                    INNER JOIN user as u 
                    ON d.user_id = u.user_id
                    INNER JOIN vehicle as v 
                    ON v.vehicle_id = i.vehicle_id
                    INNER JOIN (SELECT rating_user_id, ROUND(AVG(rating),2) as average_rating FROM rating GROUP BY rating_user_id) as r
                    ON r.rating_user_id = d.user_id";
        $q .=     " WHERE driver_id = ? ";

        if(isset($order)){
            $q .= " ORDER BY " .$order;
        } else {
            $q .= " ORDER BY itinerary_status";
        }

        //echo $q;

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
        $q = "SELECT itinerary_id, i.driver_id, i.vehicle_id, r.average_rating, v.type as vehicle_type, i.customer_id, start_address, start_address_lat, start_address_long,
            pick_up_address, pick_up_address_lat, pick_up_address_long, drop_address, drop_address_lat, drop_address_long,
            end_address, end_address_lat, end_address_long, leave_date, duration, distance, cost, description, i.status as itinerary_status, i.created_at,
            driver_license, driver_license_img, u.user_id, u.email, u.fullname, u.phone, personalID, link_avatar ";
        $q .=    "FROM i_itinerary as i
                    INNER JOIN driver as d 
                    ON i.driver_id = d.user_id
                    INNER JOIN user as u 
                    ON d.user_id = u.user_id
                    INNER JOIN vehicle as v 
                    ON v.vehicle_id = i.vehicle_id
                    INNER JOIN (SELECT rating_user_id, ROUND(AVG(rating),2) as average_rating FROM rating GROUP BY rating_user_id) as r
                    ON r.rating_user_id = d.user_id ";
        $q .=     " WHERE customer_id = ? ";
        
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $customer_id);
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
        $q = "SELECT status FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        $stmt->execute();
        $stmt->bind_result($status);
        $stmt->close();
        switch ($status) {
            case '1':
                $table_name = 'i_created_'.$table_name;
                break;
            case '2':
                $table_name = 'i_joinning';
                break;
            case '3':
                $table_name = 'i_accepted';
                break;
            case '4':
                $table_name = 'i_completed';
                break;
            default:
                return NULL;
                break;
        }
        
        
        $q = "UPDATE ".$table_name." set start_address = ?, end_address = ?, leave_day = ?, duration = ?, cost = ?, description = ? 
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
        $q = "SELECT status, table_name FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        $stmt->execute();
        $stmt->bind_result($status, $table_name);
        $stmt->fetch();
        $stmt->close();

        switch ($status) {
            case '1':
                $table_name = 'i_created_'.$table_name;
                break;
            case '2':
                $table_name = 'i_joinning';
                break;
            case '3':
                $table_name = 'i_accepted';
                break;
            case '4':
                $table_name = 'i_completed';
                break;
            default:
                break;
        }

        $q = "UPDATE ".$table_name." SET ";
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

        $nq .= " WHERE itinerary_id = {$itinerary_id}";

        $stmt = $this->conn->prepare($nq);
        
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    public function checkItineraryStatus($itinerary_id){
        $q = "SELECT status FROM i_itinerary WHERE itinerary_id = ?";
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
        $q = "SELECT status, table_name FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        $stmt->execute();
        $stmt->bind_result($status, $table_name);
        $stmt->fetch();
        $stmt->close();

        switch ($status) {
            case '1':
                $table_name = 'itinerary_created_'.$table_name;
                break;
            case '2':
                $table_name = 'itinerary_joinning';
                break;
            case '3':
                $table_name = 'itinerary_accepted';
                break;
            case '4':
                $table_name = 'itinerary_completed';
                break;
            default:
                break;
        }

        $itinerary = $this->getItinerary($itinerary_id);

        $q = "INSERT INTO itinerary_joinning (itinerary_id, start_address, start_address_lat, start_address_long, 
            end_address, end_address_lat, end_address_long, pick_up_address, pick_up_address_lat, pick_up_address_long, 
            drop_address, drop_address_lat, drop_address_long, leave_date, duration, cost, description, distance) 
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        $stmt = $this->conn->prepare($q);

        $stmt->bind_param("isddsddsddsddsidsd",
            $itinerary['itinerary_id'], $itinerary['start_address'], $itinerary['start_address_lat'], $itinerary['start_address_long'], 
            $itinerary['end_address'], $itinerary['end_address_lat'], $itinerary['end_address_long'], $itinerary['pick_up_address'], 
            $itinerary['pick_up_address_lat'], $itinerary['pick_up_address_long'], $itinerary['drop_address'], $itinerary['drop_address_lat'], 
            $itinerary['drop_address_long'], $itinerary['leave_date'], $itinerary['duration'], $itinerary['cost'], 
            $itinerary['description'], $itinerary['distance']);

        $stmt->execute();
        $stmt->close();

        $q = "DELETE FROM ".$table_name." WHERE itinerary_id = ?";

        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        
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
        $q = "SELECT status, table_name FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        $stmt->execute();
        $stmt->bind_result($status, $table_name);
        $stmt->fetch();
        $stmt->close();

        $table_name1 = 'itinerary_created_'.$table_name;

        switch ($status) {
            case '1':
                $table_name = 'itinerary_created_'.$table_name;
                break;
            case '2':
                $table_name = 'itinerary_joinning';
                break;
            case '3':
                $table_name = 'itinerary_accepted';
                break;
            case '4':
                $table_name = 'itinerary_completed';
                break;
            default:
                break;
        }

        $itinerary = $this->getItinerary($itinerary_id);

        $q = "INSERT INTO ".$table_name1." (itinerary_id, start_address, start_address_lat, start_address_long, 
            end_address, end_address_lat, end_address_long, pick_up_address, pick_up_address_lat, pick_up_address_long, 
            drop_address, drop_address_lat, drop_address_long, leave_date, duration, cost, description, distance) 
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        $stmt = $this->conn->prepare($q);

        $stmt->bind_param("isddsddsddsddsidsd",
            $itinerary['itinerary_id'], $itinerary['start_address'], $itinerary['start_address_lat'], $itinerary['start_address_long'], 
            $itinerary['end_address'], $itinerary['end_address_lat'], $itinerary['end_address_long'], $itinerary['pick_up_address'], 
            $itinerary['pick_up_address_lat'], $itinerary['pick_up_address_long'], $itinerary['drop_address'], $itinerary['drop_address_lat'], 
            $itinerary['drop_address_long'], $itinerary['leave_date'], $itinerary['duration'], $itinerary['cost'], 
            $itinerary['description'], $itinerary['distance']);

        $stmt->execute();
        $stmt->close();

        $q = "DELETE FROM ".$table_name." WHERE itinerary_id = ?";

        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        
        //ITINERARY_STATUS_CUSTOMER_ACCEPTED
        $q = "UPDATE itinerary set customer_id = NULL, status = 1 
                WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    public function updateCustomerEndItinerary($itinerary_id) {
        $q = "SELECT status, table_name FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        $stmt->execute();
        $stmt->bind_result($status, $table_name);
        $stmt->fetch();
        $stmt->close();

        $table_name1 = 'itinerary_created_'.$table_name;

        switch ($status) {
            case '1':
                $table_name = 'itinerary_created_'.$table_name;
                break;
            case '2':
                $table_name = 'itinerary_joinning';
                break;
            case '3':
                $table_name = 'itinerary_accepted';
                break;
            case '4':
                $table_name = 'itinerary_completed';
                break;
            default:
                break;
        }

        $itinerary = $this->getItinerary($itinerary_id);

        $q = "INSERT INTO itinerary_completed (itinerary_id, start_address, start_address_lat, start_address_long, 
            end_address, end_address_lat, end_address_long, pick_up_address, pick_up_address_lat, pick_up_address_long, 
            drop_address, drop_address_lat, drop_address_long, leave_date, duration, cost, description, distance) 
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        $stmt = $this->conn->prepare($q);

        $stmt->bind_param("isddsddsddsddsidsd",
            $itinerary['itinerary_id'], $itinerary['start_address'], $itinerary['start_address_lat'], $itinerary['start_address_long'], 
            $itinerary['end_address'], $itinerary['end_address_lat'], $itinerary['end_address_long'], $itinerary['pick_up_address'], 
            $itinerary['pick_up_address_lat'], $itinerary['pick_up_address_long'], $itinerary['drop_address'], $itinerary['drop_address_lat'], 
            $itinerary['drop_address_long'], $itinerary['leave_date'], $itinerary['duration'], $itinerary['cost'], 
            $itinerary['description'], $itinerary['distance']);

        $stmt->execute();
        $stmt->close();

        $q = "DELETE FROM itinerary_accepted WHERE itinerary_id = ?";

        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        
        //ITINERARY_STATUS_CUSTOMER_ACCEPTED
        $q = "UPDATE itinerary set customer_id = NULL, status = 4 
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
        $q = "SELECT status, table_name FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        $stmt->execute();
        $stmt->bind_result($status, $table_name);
        $stmt->fetch();
        $stmt->close();

        switch ($status) {
            case '1':
                $table_name = 'itinerary_created_'.$table_name;
                break;
            case '2':
                $table_name = 'itinerary_joinning';
                break;
            case '3':
                $table_name = 'itinerary_accepted';
                break;
            case '4':
                $table_name = 'itinerary_completed';
                break;
            default:
                break;
        }

        $itinerary = $this->getItinerary($itinerary_id);

        $q = "INSERT INTO itinerary_accepted (itinerary_id, start_address, start_address_lat, start_address_long, 
            end_address, end_address_lat, end_address_long, pick_up_address, pick_up_address_lat, pick_up_address_long, 
            drop_address, drop_address_lat, drop_address_long, leave_date, duration, cost, description, distance) 
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        $stmt = $this->conn->prepare($q);

        $stmt->bind_param("isddsddsddsddsidsd",
            $itinerary['itinerary_id'], $itinerary['start_address'], $itinerary['start_address_lat'], $itinerary['start_address_long'], 
            $itinerary['end_address'], $itinerary['end_address_lat'], $itinerary['end_address_long'], $itinerary['pick_up_address'], 
            $itinerary['pick_up_address_lat'], $itinerary['pick_up_address_long'], $itinerary['drop_address'], $itinerary['drop_address_lat'], 
            $itinerary['drop_address_long'], $itinerary['leave_date'], $itinerary['duration'], $itinerary['cost'], 
            $itinerary['description'], $itinerary['distance']);

        $stmt->execute();
        $stmt->close();

        $q = "DELETE FROM itinerary_joinning WHERE itinerary_id = ?";

        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        
        //ITINERARY_STATUS_CUSTOMER_ACCEPTED
        $q = "UPDATE itinerary set status = 3 WHERE itinerary_id = ?";
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
    public function updateOnGoingItinerary($itinerary_id) {
        $q = "SELECT status, table_name FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        $stmt->execute();
        $stmt->bind_result($status, $table_name);
        $stmt->fetch();
        $stmt->close();

        switch ($status) {
            case '1':
                $table_name = 'itinerary_created_'.$table_name;
                break;
            case '2':
                $table_name = 'itinerary_joinning';
                break;
            case '3':
                $table_name = 'itinerary_accepted';
                break;
            case '4':
                $table_name = 'itinerary_completed';
                break;
            default:
                break;
        }

        $itinerary = $this->getItinerary($itinerary_id);

        $q = "INSERT INTO itinerary_accepted (itinerary_id, start_address, start_address_lat, start_address_long, 
            end_address, end_address_lat, end_address_long, pick_up_address, pick_up_address_lat, pick_up_address_long, 
            drop_address, drop_address_lat, drop_address_long, leave_date, duration, cost, description, distance) 
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        $stmt = $this->conn->prepare($q);

        $stmt->bind_param("isddsddsddsddsidsd",
            $itinerary['itinerary_id'], $itinerary['start_address'], $itinerary['start_address_lat'], $itinerary['start_address_long'], 
            $itinerary['end_address'], $itinerary['end_address_lat'], $itinerary['end_address_long'], $itinerary['pick_up_address'], 
            $itinerary['pick_up_address_lat'], $itinerary['pick_up_address_long'], $itinerary['drop_address'], $itinerary['drop_address_lat'], 
            $itinerary['drop_address_long'], $itinerary['leave_date'], $itinerary['duration'], $itinerary['cost'], 
            $itinerary['description'], $itinerary['distance']);

        $stmt->execute();
        $stmt->close();

        $q = "DELETE FROM itinerary_joinning WHERE itinerary_id = ?";

        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        
        //ITINERARY_STATUS_CUSTOMER_ACCEPTED
        $q = "UPDATE itinerary set status = 3 WHERE itinerary_id = ?";
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
        $q = "SELECT status, table_name FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        $stmt->execute();
        $stmt->bind_result($status, $table_name);
        $stmt->fetch();
        $stmt->close();

        $table_name1 = 'itinerary_created_'.$table_name;

        switch ($status) {
            case '1':
                $table_name = 'itinerary_created_'.$table_name;
                break;
            case '2':
                $table_name = 'itinerary_joinning';
                break;
            case '3':
                $table_name = 'itinerary_accepted';
                break;
            case '4':
                $table_name = 'itinerary_completed';
                break;
            default:
                break;
        }

        $itinerary = $this->getItinerary($itinerary_id);

        $q = "INSERT INTO ".$table_name1." (itinerary_id, start_address, start_address_lat, start_address_long, 
            end_address, end_address_lat, end_address_long, pick_up_address, pick_up_address_lat, pick_up_address_long, 
            drop_address, drop_address_lat, drop_address_long, leave_date, duration, cost, description, distance) 
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        $stmt = $this->conn->prepare($q);

        $stmt->bind_param("isddsddsddsddsidsd",
            $itinerary['itinerary_id'], $itinerary['start_address'], $itinerary['start_address_lat'], $itinerary['start_address_long'], 
            $itinerary['end_address'], $itinerary['end_address_lat'], $itinerary['end_address_long'], $itinerary['pick_up_address'], 
            $itinerary['pick_up_address_lat'], $itinerary['pick_up_address_long'], $itinerary['drop_address'], $itinerary['drop_address_lat'], 
            $itinerary['drop_address_long'], $itinerary['leave_date'], $itinerary['duration'], $itinerary['cost'], 
            $itinerary['description'], $itinerary['distance']);

        $stmt->execute();
        $stmt->close();

        $q = "DELETE FROM ".$table_name." WHERE itinerary_id = ?";

        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        
        //ITINERARY_STATUS_CUSTOMER_ACCEPTED
        $q = "UPDATE itinerary set customer_id = NULL, status = 1 
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
        $q = "SELECT table_name, status FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$itinerary_id);
        $stmt->execute();
        $stmt->bind_result($table_name, $status);
        $stmt->store_result();
        $stmt->fetch();
        $stmt->close();

        switch ($status) {
                case '1':
                    $table_name = 'itinerary_created_'.$table_name;
                    break;
                case '2':
                    $table_name = 'itinerary_joinning';
                    break;
                case '3':
                    $table_name = 'itinerary_accepted';
                    break;
                case '4':
                    $table_name = 'itinerary_completed';
                    break;
                default:
                    return NULL;
                    break;
        }

        $q = "DELETE FROM ".$table_name." WHERE itinerary_id = ?";

        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();

        $q = "DELETE FROM itinerary WHERE itinerary_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $itinerary_id);
        $stmt->execute();
        $num_affected_rows1 = $stmt->affected_rows;
        $stmt->close();

        return $num_affected_rows > 0 || $num_affected_rows1 > 0;
    }

    /* ------------- Message table ------------------ */

    public function createMessage($user_id, $to, $subject, $content) {
        $_from = $this->getUserByUserID($user_id);
        $_to = $this->getUserByEmail($to);

        if (!isset($_to['email'])) {
            return EMAIL_NOT_EXIST;
        }

        $sql_query = "INSERT INTO message(_from, _to, subject, content) values(?, ?, ?, ?)";

        // insert query
        if ($stmt = $this->conn->prepare($sql_query)) {
            $stmt->bind_param("ssss", $_from['email'], $to, $subject, $content);
            $result = $stmt->execute();
        } else {
            var_dump($this->conn->error);
        }

        $stmt->close();

        // Check for successful insertion
        if ($result) {
            // User successfully inserted
            return USER_CREATED_MESSAGE_SUCCESSFULLY;
        } else {
            // Failed to create user
            return USER_CREATE_MESSAGE_FAILED;
        }
    }

    public function getListMessage($user_id) {
        $user = $this->getUserByUserID($user_id);

        $stmt = $this->conn->prepare("SELECT m.*, u.link_avatar as from_link_avatar 
                                        FROM message as m
                                        INNER JOIN user as u ON u.email = m._from
                                        WHERE m._to = ?");

        $stmt->bind_param("s", $user['email']);

        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $vehicle = $stmt->get_result();
            $stmt->close();
            return $vehicle;
        } else {
            return NULL;
        }
    }

    public function getMessage($message_id) {
        $stmt = $this->conn->prepare("SELECT m.*, u.link_avatar as from_link_avatar 
                                        FROM message as m
                                        INNER JOIN user as u ON u.email = m._from
                                        WHERE m._to = ?");

        $stmt->bind_param("i", $message_id);

        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($_from, $_to, $subject, $content, $message_id, $created_at, $from_link_avatar);
            $stmt->fetch();
            $message = array();
            $message["message_id"] = $message_id;
            $message["_from"] = $_from;
            $message["_to"] = $type;
            $message["subject"] = $subject;
            $message["content"] = $content;
            $message["created_at"] = $created_at;
            $message["from_link_avatar"] = $from_link_avatar;
            $stmt->close();
            return $message;
        } else {
            return NULL;
        }
    }

    public function deleteMessage($message_id) {
        $stmt = $this->conn->prepare("DELETE FROM message WHERE message_id = ?");
        $stmt->bind_param("i", $message_id);
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

    public function getListFeedbacks() {
        $stmt = $this->conn->prepare("SELECT * FROM feedback");

        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $feedback = $stmt->get_result();
            $stmt->close();
            return $feedback;
        } else {
            return NULL;
        }
    }

    public function deleteFeedback($feedback_id) {
        $stmt = $this->conn->prepare("DELETE FROM feedback WHERE feedback_id = ?");
        $stmt->bind_param("i", $feedback_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /* ------------- Statistic ------------------ */

    //number of users created per month
    public function statisticUserBy() {
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
    public function statisticItineraryBy() {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, COUNT(DATE_FORMAT(created_at,'%Y-%m')) as number 
                FROM i_itinerary GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
        
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
    public function statisticMoneyBy() {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, SUM(cost) as total_money 
                FROM i_itinerary GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
        
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
    public function statisticCustomerBy($customer_id, $year) {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, COUNT(DATE_FORMAT(created_at,'%Y-%m')) as number, SUM(cost) as total_money  
                FROM (SELECT * FROM i_itinerary WHERE customer_id = ? ";


        if( $year == 'all' ) {
            $q .= " ) as i  GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
            $stmt = $this->conn->prepare($q);
            if ($stmt->bind_param("i",$customer_id)) {
                $stmt->execute();
            } else {
                var_dump($this->db->error);
            }
        } else {
            $q .= " AND DATE_FORMAT(created_at,'%Y') = ? ) as i GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
            $stmt = $this->conn->prepare($q);
            if ($stmt->bind_param("ii",$customer_id, $year)) {
                $stmt->execute();
            } else {
                var_dump($this->db->error);
            }
        }

        $results = $stmt->get_result();

        $stats = array();
        // looping through result and preparing tasks array
        while ($stat = $results->fetch_assoc()) {
            $tmp = array();

            $tmp["month"] = $stat["month"];
            $tmp["number"] = $stat["number"];
            $tmp["total_money"] = $stat["total_money"];
            array_push($stats, $tmp);
        }

        $stmt->close();
        return $stats;
    }


    public function statisticCustomerAll($customer_id) {
        $q = "SELECT DATE_FORMAT(created_at,'%Y') as year, COUNT(DATE_FORMAT(created_at,'%Y')) as number, SUM(cost) as total_money  
                FROM (SELECT * FROM i_itinerary WHERE customer_id = ? ";


        
        $q .= " ) as i  GROUP BY DATE_FORMAT(created_at,'%Y')";
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

            $tmp["year"] = $stat["year"];
            $tmp["number"] = $stat["number"];
            $tmp["total_money"] = $stat["total_money"];
            array_push($stats, $tmp);
        }

        $stmt->close();
        return $stats;
    }

    //total money come frome itineraries per month
    /*public function statisticCustomerMoneyBy($customer_id, $year) {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, SUM(cost) as total_money 
                FROM (SELECT * FROM i_itinerary WHERE customer_id = ? ";
        
        if( $year == 'all' ) {
            $q .= " ) as i GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
            $stmt = $this->conn->prepare($q);
            if ($stmt->bind_param("i",$customer_id)) {
                $stmt->execute();
            } else {
                var_dump($this->db->error);
            }
        } else {
            $q .= " AND DATE_FORMAT(created_at,'%Y') = ? ) as i GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
            $stmt = $this->conn->prepare($q);
            if ($stmt->bind_param("ii",$customer_id, $year)) {
                $stmt->execute();
            } else {
                var_dump($this->db->error);
            }
        }


        //$stmt = $this->conn->prepare($q);
        //if ($stmt->bind_param("i",$customer_id)) {
        //    $stmt->execute();
        //} else {
        //    var_dump($this->db->error);
        //}
        
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
    }*/

    //Driver Staticstic
    //number of itineraries creted per month
    public function statisticDriverBy($driver_id, $year) {

        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, COUNT(DATE_FORMAT(created_at,'%Y-%m')) as number, SUM(cost) as total_money  
                FROM (SELECT * FROM i_itinerary WHERE driver_id = ? ";

        if( $year == 'all' ) {
            $q .= " ) as i GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
            $stmt = $this->conn->prepare($q);
            $stmt->bind_param("i",$driver_id);
        } else {
            $q .= " AND DATE_FORMAT(created_at,'%Y') = ? ) as i GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
            $stmt = $this->conn->prepare($q);
            $stmt->bind_param("ii",$driver_id, $year);
        }
        
        //$stmt->bind_param("i",$driver_id);
        
        $stmt->execute();
        $results = $stmt->get_result();

        $stats = array();
        // looping through result and preparing tasks array
        while ($stat = $results->fetch_assoc()) {
            $tmp = array();

            $tmp["month"] = $stat["month"];
            $tmp["number"] = $stat["number"];
            $tmp["total_money"] = $stat["total_money"];
            array_push($stats, $tmp);
        }

        $stmt->close();
        return $stats;
    }

    public function statisticDriverAll($driver_id) {

        $q = "SELECT DATE_FORMAT(created_at,'%Y') as year, COUNT(DATE_FORMAT(created_at,'%Y')) as number, SUM(cost) as total_money  
                FROM (SELECT * FROM i_itinerary WHERE driver_id = ? ";

        
        $q .= " ) as i GROUP BY DATE_FORMAT(created_at,'%Y')";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i",$driver_id);
        
        
        //$stmt->bind_param("i",$driver_id);
        
        $stmt->execute();
        $results = $stmt->get_result();

        $stats = array();
        // looping through result and preparing tasks array
        while ($stat = $results->fetch_assoc()) {
            $tmp = array();

            $tmp["year"] = $stat["year"];
            $tmp["number"] = $stat["number"];
            $tmp["total_money"] = $stat["total_money"];
            array_push($stats, $tmp);
        }

        $stmt->close();
        return $stats;
    }

    //total money come frome itineraries per month
    /*public function statisticDriverMoneyBy($driver_id, $year) {
        $q = "SELECT DATE_FORMAT(created_at,'%Y-%m') as month, SUM(cost) as total_money 
                FROM (SELECT * FROM i_itinerary WHERE driver_id = ? ";
        
        if( $year == 'all' ) {
            $q .= " ) as i GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
            $stmt = $this->conn->prepare($q);
            $stmt->bind_param("i",$driver_id);
        } else {
            $q .= " AND DATE_FORMAT(created_at,'%Y') = ? ) as i GROUP BY DATE_FORMAT(created_at,'%Y-%m')";
            $stmt = $this->conn->prepare($q);
            $stmt->bind_param("ii",$driver_id, $year);
        }

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
    }*/


    /* ------------- `Comment` table method ------------------ */

    public function createComment($user_id, $content, $comment_about_user_id) {
        // First check if user already existed in db

            $sql_query = "INSERT INTO comment(user_comment_id, comment_about_user_id, content) values(?, ?, ?)";

            // insert query
            if ($stmt = $this->conn->prepare($sql_query)) {
                $stmt->bind_param("iis", $user_id, $comment_about_user_id, $content==NULL?'':$content);
                $result = $stmt->execute();
            } else {
                var_dump($this->conn->error);
            }

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return COMMENT_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return COMMENT_CREATE_FAILED;
            }
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getListCommentOfUser($user_id) {
        $stmt = $this->conn->prepare("SELECT * FROM comment WHERE user_comment_id = ?");

        $stmt->bind_param("i", $user_id);

        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $vehicle = $stmt->get_result();
            $stmt->close();
            return $vehicle;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getListCommentAboutUser($user_id) {
        $stmt = $this->conn->prepare("SELECT * FROM comment WHERE comment_about_user_id = ?");

        $stmt->bind_param("i", $user_id);

        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $vehicle = $stmt->get_result();
            $stmt->close();
            return $vehicle;
        } else {
            return NULL;
        }
    }

    public function getListComment() {
        $stmt = $this->conn->prepare("SELECT c.*, u1.fn1, u2.fn2 FROM comment as c 
                            INNER JOIN (SELECT user_id, fullname as fn1 from user) as u1 ON u1.user_id = c.user_comment_id
                            INNER JOIN (SELECT user_id, fullname as fn2 from user) as u2 ON u2.user_id = c.comment_about_user_id");

        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $comments = $stmt->get_result();
            $stmt->close();
            return $comments;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getComment($comment_id) {
        $stmt = $this->conn->prepare("SELECT comment_id, user_comment_id, comment_about_user_id, content, created_at
                                      FROM comment WHERE comment_id = ?");

        $stmt->bind_param("i", $comment_id);

        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($comment_id, $user_comment_id, $comment_about_user_id, $content, $created_at);
            $stmt->fetch();
            $commnent = array();
            $commnent["comment_id"] = $comment_id;
            $commnent["user_comment_id"] = $user_comment_id;
            $commnent["comment_about_user_id"] = $comment_about_user_id;
            $commnent["content"] = $content; 
            $commnent["created_at"] = $created_at;
            $stmt->close();
            return $commnent;
        } else {
            return NULL;
        }
    }

    public function updateComment($comment_id, $content) {
        require_once '/Config.php';
        $conn2 = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8", DB_USERNAME, DB_PASSWORD);
        // set the PDO error mode to exception
        $conn2->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $qry = "UPDATE vehicle set";
        $param = array();

        if (isset($content)) { 
            $qry .= " content = :content,"; 
        }

        $qry .= " status = 1 WHERE comment_id = :comment_id";

        $stmt = $conn2->prepare($qry);

        if (isset($content)) { 
            $stmt->bindParam(':content', $content);
        }

        $stmt->bindParam(':comment_id', $comment_id);
        $stmt->execute();
        $num_affected_rows = $stmt->rowCount();
        $conn2 = null;
        return $num_affected_rows > 0;
    }

    /**
     * Delete driver
     * @param String $user_id id of user
     */
    public function deleteComment($comment_id) {
        $stmt = $this->conn->prepare("DELETE FROM comment WHERE comment_id = ?");
        $stmt->bind_param("i", $comment_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }


    /* ------------- `Rating` table method ------------------ */

    public function createRating($user_id, $rating, $rating_user_id) {
        // First check if user already existed in db

            $sql_query = "INSERT INTO rating(user_id, rating_user_id, rating) values(?, ?, ?)";

            // insert query
            if ($stmt = $this->conn->prepare($sql_query)) {
                $stmt->bind_param("iii", $user_id, $rating_user_id, $rating);
                $result = $stmt->execute();
            } else {
                var_dump($this->conn->error);
            }

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return RATING_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return RATING_CREATE_FAILED;
            }
    }

    public function getAverageRatingofUser($user_id){
        $q = "SELECT AVG(rating) FROM rating group by rating_user_id having rating_user_id = ?";
        $stmt = $this->conn->prepare($q);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();

        $stmt->bind_result($average_rating);
        $stmt->fetch();
        $stmt->close();

        if($average_rating == null){
            return 0;
        } else {
            return round($average_rating,2);
        }
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getRating($user_id, $rating_user_id) {
        $stmt = $this->conn->prepare("SELECT rating FROM rating WHERE user_id = ? AND rating_user_id = ?");

        $stmt->bind_param("ii", $user_id, $rating_user_id);

        if ($stmt->execute()) {

            $stmt->bind_result($rating);
            $stmt->close();
            if($rating == null){
                return 0;
            } else {
                return $rating;
            }
        } else {
            return NULL;
        }
    }


    /**
     * Delete driver
     * @param String $user_id id of user
     */
    public function deleteRating($rating_id) {
        $stmt = $this->conn->prepare("DELETE FROM rating WHERE rating_id = ?");
        $stmt->bind_param("i", $rating_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
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
