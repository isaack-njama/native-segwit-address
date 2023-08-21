<?php

require_once 'vendor/autoload.php';

use BitWasp\Bitcoin\Address\SegwitAddress;
use BitWasp\Bitcoin\Crypto\Random\Random;
use BitWasp\Bitcoin\Key\Factory\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39Mnemonic;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use BitWasp\Bitcoin\Script\WitnessProgram;

// $mnemonic = 'suspect copyright athlete murder grass tactic syndrome blue overall investigation visual housewife';

// Generate a mnemonic
$random = new Random();
$entropy = $random->bytes(Bip39Mnemonic::MAX_ENTROPY_BYTE_LEN);

// 12-word seed
$bip39 = MnemonicFactory::bip39();
$mnemonic = $bip39->entropyToMnemonic($entropy);

// Generate the BIP39 seed from the mnemonic
$seedGenerator = new Bip39SeedGenerator();
$seed = $seedGenerator->getSeed($mnemonic);

// Derive the master key from the seed
$hdFactory = new HierarchicalKeyFactory();
$masterKey = $hdFactory->fromEntropy($seed);

// Derive the purpose key (m/84'/0'/0')
$purposeKey = $masterKey->derivePath("84'/0'/0'");

// Derive the account key (m/84'/0'/0'/0)
$accountKey = $purposeKey->derivePath('0');

// Derive the external key (m/84'/0'/0'/0/0)
$externalKey = $accountKey->derivePath('0');

// Get the public key from the external key
$publicKey = $externalKey->getPublicKey();

// Derive the public key hash
$publicKeyHash = $publicKey->getPubKeyHash();

// Derive the native segwit address
$p2wpkhWP = WitnessProgram::v0($publicKeyHash);
$p2wpkh = new SegwitAddress($p2wpkhWP);
$address = $p2wpkh->getAddress();

echo 'Native SegWit / P2WPKH Address: ' . $address . "\n";

?>