# Peach AES 256 GCM without libsodium

## Example usage in magento (using peach examples)

```php

$cryptKey = '000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F';
$cryptIv = '3D575574536D450F71AC76D8';
$cryptPayload = 'F8E2F759E528CB69375E51DB2AF9B53734E393';


$decrypt = Mage::getSingleton('peach_aes/decrypt');
$decrypted = json_decode($decrypt->getDecryptedPayload($cryptKey, $cryptIv, $cryptPayload), true);


// >>> echo $decrypt->getDecryptedPayload($cryptKey, $cryptIv, $cryptPayload);
// => "{"type": "PAYMENT"}"

```

## Non magento usage

If you simply want to use the class, just use and rename the class at app/code/community/Peach/AES/Module/Decrypt.php