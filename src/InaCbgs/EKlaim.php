<?php
namespace Purnama97\InaCbgs;
use Purnama97\InaCbg\InaCbgService;

class EKlaim extends InaCbgService
{
    public function testDekrtip($data = [])
    {
        $response = $this->post('test', $data);
        return json_decode($response, true);
    }
}