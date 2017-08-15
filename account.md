### 以太坊账号创建和加密过程

以太坊的账号主要包含的信息有ID，地址（Address）,公私密钥对(PrivateKey),代码中定义如下：
```
type Key struct {
	Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// to simplify lookups we also store the address
	Address common.Address
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	PrivateKey *ecdsa.PrivateKey
}
```

可以使用如下命令，新建一个账号，这个过程会让用户输入一个密码:
```
geth account new 
```
其结果将在keystore目录下生成一个json文件，文件名就是的账号地址，内容是：
```json
{
    "address": "59870e7df0fa152f59547d68b57bb38a0a7bce80", //地址
    "crypto": {
        "cipher": "aes-128-ctr",
        "ciphertext": "5c878700fbd14d7574e47e4a8bab42ab005c4a93140fe65a5bd00e450a912f12",
        "cipherparams": {
            "iv": "212d763889332a125d836254aebe4fc2"
        },
        "kdf": "scrypt",
        "kdfparams": {
            "dklen": 32, 
            "n": 262144,
            "p": 1,
            "r": 8,
            "salt": "1aceb182b9e80bf4189ddb1c5c31d4a3642c2a3dcabfceeb8ff709ac2c5d7718"
        },
        "mac": "1c23efad3cddd86e3af7d4e45bf81a5d5679c68d92599f5094311a6dd7a6c67c"
    },
    "id": "20fead9e-187e-4522-b2cf-e3c75ac71058",
    "version": 3
}
```
整个过程大概是：
```
1，用户输入一个密码
2，内部通过椭圆曲线算法随机生成一个公私密钥对
3，对公钥hash得到地址
4，对密码使用scrypt算法加密,得到加密后的密码derivedKey
5，用derivedKey的对私钥使用AES-CTR算法加密，得到密文cipherText
6，对derivedKey和cipherText进行hash得到mac，这个mac实际上起到了签名的作用，在解密的时候去验证合法性，防止别人篡改
7，保存账号地址和加密过程中写死或随机生成的参数到json文件中，也就是就是上面的文件
```

### 核心代码
以太坊使用scrypt算法加密密码，scrypt算法描述如下：

输入：
```
P 密码短语，一个字节串
S 盐，一个字节串
N CPU/内存消耗参数，必须大于1, 是2的n次幂并且小于2^(128*r/8)
r 块容量参数
p 并行化参数，一个小于等于((2^32-1)*hLen)/MFLen的正整数，其中hLen为32，MFlen是128*r。（在ltc协议中 p = 1）
dkLen 期望输出的派生密钥的字节长度；一个小于等于(2^32 - 1) * hLen的正整数，其中hLen为32
```
输出：
```
DK 派生密钥， 长度为dkLen个字节
```

以太坊创建账号的核心代码如下：
```go
// key，加密的账号，里面包含了ID，公私钥，地址
// auth，用户名输入的密码，对应scrypt算法中的P
// scryptN，scrypt算法中的N
// scryptP，scrypt算法中的p

func EncryptKey(key *Key, auth string, scryptN, scryptP int) ([]byte, error) {
	authArray := []byte(auth)       
	
	//随机生成盐
	salt := randentropy.GetEntropyCSPRNG(32) 
	
	//对用户名输入的密码使用scrypt加密，并返回一个derivedKey
	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return nil, err
	}
	
	//取前16byte
	encryptKey := derivedKey[:16]
	
	//取出私钥中的数据
	keyBytes := math.PaddedBigBytes(key.PrivateKey.D, 32)
    
    //使用AE-CTR算法加密私钥
	iv := randentropy.GetEntropyCSPRNG(aes.BlockSize)
	cipherText, err := aesCTRXOR(encryptKey, keyBytes, iv)
	if err != nil {
		return nil, err
	}
	
	//通过密码和私钥hash生成mac
	mac := crypto.Keccak256(derivedKey[16:32], cipherText)


    //保存数据成json格式
	scryptParamsJSON := make(map[string]interface{}, 5)
	scryptParamsJSON["n"] = scryptN
	scryptParamsJSON["r"] = scryptR
	scryptParamsJSON["p"] = scryptP
	scryptParamsJSON["dklen"] = scryptDKLen
	scryptParamsJSON["salt"] = hex.EncodeToString(salt)

	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	cryptoStruct := cryptoJSON{
		Cipher:       "aes-128-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          "scrypt",
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
	}
	encryptedKeyJSONV3 := encryptedKeyJSONV3{
		hex.EncodeToString(key.Address[:]),
		cryptoStruct,
		key.Id.String(),
		version,
	}
	return json.Marshal(encryptedKeyJSONV3)
}
```
