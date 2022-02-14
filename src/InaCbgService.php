<?php
namespace Purnama97\InaCbg;
use GuzzleHttp\Client;

class InaCbgService{

    /**
     * Guzzle HTTP Client object
     * @var \GuzzleHttp\Client
     */
    private $clients;

    /**
     * Request headers
     * @var array
     */
    private $headers;

    /**
     * X-cons-id header value
     * @var int
     */
    private $key;

    /**
     * @var string
     */
    private $base_url;

    public function __construct($configurations)
    {
        $this->clients = new Client([
            'verify' => false
        ]);

        foreach ($configurations as $key => $val){
            if (property_exists($this, $key)) {
                $this->$key = $val;
            }
        }

        //set X-Timestamp, X-Signature, and finally the headers
        $this->setTimestamp()->setSignature()->setHeaders();
    }

    protected function setHeaders()
    {
        $this->headers = [
            'X-cons-id' => $this->key,
        ];
        return $this;
    }

    function inacbg_encrypt($data, $key) 
    { 
 
        /// make binary representasion of $key 
        $key = hex2bin($key); 
        /// check key length, must be 256 bit or 32 bytes 
        if (mb_strlen($key, "8bit") !== 32) { 
            throw new Exception("Needs a 256-bit key!"); 
        } 
        /// create initialization vector 
        $iv_size = openssl_cipher_iv_length("aes-256-cbc"); 
        $iv = openssl_random_pseudo_bytes($iv_size); // dengan catatan dibawah 
        /// encrypt 
        $encrypted = openssl_encrypt($data, "aes-256-cbc", $key, OPENSSL_RAW_DATA, $iv ); 
        /// create signature, against padding oracle attacks 
        $signature = mb_substr(hash_hmac("sha256", $encrypted, $key, true),0,10,"8bit");
        /// combine all, encode, and format 
        $encoded = chunk_split(base64_encode($signature.$iv.$encrypted)); 
        
        return $encoded; 
    }

    function inacbg_decrypt($str, $strkey)
    { 
        /// make binary representation of $key 
        $key = hex2bin($strkey); 
        /// check key length, must be 256 bit or 32 bytes 
        if (mb_strlen($key, "8bit") !== 32) { 
            throw new Exception("Needs a 256-bit key!"); 
        } 
        /// calculate iv size 
        $iv_size = openssl_cipher_iv_length("aes-256-cbc"); 

        /// breakdown parts 
        $decoded = base64_decode($str); 
        $signature = mb_substr($decoded,0,10,"8bit"); 
        $iv = mb_substr($decoded,10,$iv_size,"8bit"); 
        $encrypted = mb_substr($decoded,$iv_size+10,NULL,"8bit"); 

        /// check signature, against padding oracle attack 
        $calc_signature = mb_substr(hash_hmac("sha256", $encrypted, $key, true),0,10,"8bit");
        if(!inacbg_compare($signature,$calc_signature)) { 
            return "SIGNATURE_NOT_MATCH"; /// signature doesn't match 
        } 

        $decrypted = openssl_decrypt($encrypted, "aes-256-cbc", $key, OPENSSL_RAW_DATA, $iv); 
        return $decrypted; 
    } 

    function inacbg_compare($a, $b) { 
        /// compare individually to prevent timing attacks 
        
        /// compare length 
        if (strlen($a) !== strlen($b)) return false; 
        
        /// compare individual 
        $result = 0; 
        for($i = 0; $i < strlen($a); $i ++) { 
        $result |= ord($a[$i]) ^ ord($b[$i]); 
        } 
        
        return $result == 0; 
    }


    protected function get($feature)
    {
        $this->headers['Content-Type'] = 'application/json; charset=utf-8';
        try {
            // $data = $this->clients->request(
            //     'GET',
            //     $this->base_url . '/' . $this->service_name . '/' . $feature,
            //     [
            //         'headers' => $this->headers
            //     ]
            // )->getBody()->getContents();
            // // var_dump($data);
            // $key = $this->headers['X-cons-id'] . $this->secret_key . $this->headers['X-Timestamp'];
            $response = $this->inacbg_decrypt(json_decode($data), $this->key);
        } catch (\Exception $e) {
            $response = $e->getResponse()->getBody();
        }
       
        return $response;
    }

    protected function post($feature, $data = [], $headers = [])
    {
        $this->headers['Content-Type'] = 'application/x-www-form-urlencoded';
        if(!empty($headers)){
            $this->headers = array_merge($this->headers,$headers);
        }
        try {
        //     $data = $this->clients->request(
        //         'POST',
        //         $this->base_url . '/' . $this->service_name . '/' . $feature,
        //         [
        //             'headers' => $this->headers,
        //             'json' => $data,
        //         ]
        //     )->getBody()->getContents();
        //     $key = $this->headers['X-cons-id'] . $this->secret_key . $this->headers['X-Timestamp'];
        //     $response = $this->stringDecrypt($key, json_decode($data));
            $response = $this->inacbg_decrypt(json_decode($data), $this->key);
        } catch (\Exception $e) {
            $response = $e->getResponse()->getBody();
        }
        return $response;
    }

    protected function put($feature, $data = [])
    {
        $this->headers['Content-Type'] = 'application/x-www-form-urlencoded';
        try {
            // $data = $this->clients->request(
            //     'PUT',
            //     $this->base_url . '/' . $this->service_name . '/' . $feature,
            //     [
            //         'headers' => $this->headers,
            //         'json' => $data,
            //     ]
            // )->getBody()->getContents();

            // $key = $this->headers['X-cons-id'] . $this->secret_key . $this->headers['X-Timestamp'];
            // $response = $this->stringDecrypt($key, json_decode($data));
            $response = $this->inacbg_decrypt(json_decode($data), $this->key);
        } catch (\Exception $e) {
            $response = $e->getResponse()->getBody();
        }
        return $response;
    }


    protected function delete($feature, $data = [])
    {
        $this->headers['Content-Type'] = 'application/x-www-form-urlencoded';
        try {
            // $response = $this->clients->request(
            //     'DELETE',
            //     $this->base_url . '/' . $this->service_name . '/' . $feature,
            //     [
            //         'headers' => $this->headers,
            //         'json' => $data,
            //     ]
            // )->getBody()->getContents();
            $response = $this->inacbg_decrypt(json_decode($data), $this->key);
        } catch (\Exception $e) {
            $response = $e->getResponse()->getBody();
        }
        return $response;
    }

}
