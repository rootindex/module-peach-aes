<?php
/**
 * 🔒 Copyright (c) 2018 Francois Raubenheimer. All rights reserved.
 */

/**
 * Class Peach_AES_Model_Decrypt
 */
class Peach_AES_Model_Decrypt
{
    /**
     * Get decrypted payload.
     *
     * We will not validate a single thing to speed up the process.
     *
     * @return bool|string
     */
    public function getDecryptedPayload($key, $iv, $payload)
    {
        $key = $this->getBinaryKey($key);
        $iv = $this->getBinaryIv($iv);
        $payload = $this->getBinaryPayload($payload);

        return $this->getGCTR($key, $this->getInc(32, $iv . pack('H*', '00000001')), $payload);
    }

    /**
     * @param string $key
     * @param string $icb
     * @param string $payload
     *
     * @return string
     */
    private function getGCTR($key, $icb, $payload)
    {
        if (empty($payload)) {
            return '';
        }
        $CB = [];
        $Y = [];

        $n = (int)ceil($this->getLength($payload) / 128);

        $CB[1] = $icb;

        for ($i = 2; $i <= $n; $i++) {
            $CB[$i] = $this->getInc(32, $CB[$i - 1]);
        }

        for ($i = 1; $i < $n; $i++) {
            $C = openssl_encrypt($CB[$i], 'aes-256-ecb', $key, OPENSSL_NO_PADDING | OPENSSL_RAW_DATA);
            $Y[$i] = $this->getBitXor(mb_substr($payload, ($i - 1) * 16, 16, '8bit'), $C);
        }

        $Xn = mb_substr($payload, ($n - 1) * 16, null, '8bit');
        $C = openssl_encrypt($CB[$n], 'aes-256-ecb', $key, OPENSSL_NO_PADDING | OPENSSL_RAW_DATA);
        $Y[$n] = $this->getBitXor($Xn, $this->getMSB($this->getLength($Xn), $C));

        return implode('', $Y);
    }

    /**
     * @param string $o1
     * @param string $o2
     *
     * @return string
     */
    private static function getBitXor($o1, $o2)
    {
        $xorWidth = PHP_INT_SIZE;
        $o1 = str_split($o1, $xorWidth);
        $o2 = str_split($o2, $xorWidth);
        $res = '';
        $runs = count($o1);
        for ($i = 0; $i < $runs; $i++) {
            $res .= $o1[$i] ^ $o2[$i];
        }

        return $res;
    }

    /**
     * @param int $sBits
     * @param $x
     * @return string
     */
    private function getInc($sBits, $x)
    {
        $lsb = mb_substr($x, -($sBits / 8), null, '8bit');

        list(, $h, $l) = unpack('n*', $lsb);
        $xx = ($l + ($h * 0x010000)) + 1;

        $res = $this->getMSB($this->getLength($x) - $sBits, $x) . pack('N', $xx);

        return $res;
    }

    /**
     * @param int $numBits
     * @param int $x
     *
     * @return string
     */
    private function getMSB($numBits, $x)
    {
        return mb_substr($x, 0, $numBits / 8, '8bit');
    }

    /**
     * Get length.
     *
     * @param $k
     * @return float|int
     */
    private function getLength($k)
    {
        return mb_strlen($k, '8bit') * 8;
    }

    /**
     * Get tag length.
     *
     * @param string $tag
     * @return float|int
     */
    public function getTagLength($tag)
    {
        return $this->getLength($tag);
    }

    /**
     * Convert hexadecimal key to binary
     * @param string $key
     * @return bool|string
     */
    private function getBinaryKey($key)
    {
        return hex2bin($key);
    }

    /**
     * Convert hexadecimal iv to binary
     *
     * @param string $iv
     * @return bool|string
     */
    private function getBinaryIv($iv)
    {
        return hex2bin($iv);
    }

    /**
     * Convert hexadecimal payload to binary
     *
     * @param string $payload
     * @return bool|string
     */
    private function getBinaryPayload($payload)
    {
        return hex2bin($payload);
    }
}