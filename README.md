# WinRT component implementation of Javascript Object Signing and Encryption (JOSE) and JSON Web Token (JWT)

##Credits

## Supported JWA algorithms

**Signing**
- HMAC signatures with HS256, HS384 and HS512.
- RSASSA-PKCS1-V1_5 signatures with RS256, RS384 and RS512.
- RSASSA-PSS signatures with PS256, PS384 and PS512<sup>\*</sup>
- ECDSA signatures with ES256, ES384 and ES512.

##### Notes:
\* It appears that Microsoft implementation of AsymmetricAlgorithmNames.RsaSignPssSha256, AsymmetricAlgorithmNames.RsaSignPssSha384 and AsymmetricAlgorithmNames.RsaSignPssSha512
is broken. At least produced signatures can't be validated on other platforms. **jose-rt** provides support for PS256, PS384 and PS512 but most likely produced tokens can't be decoded correctly with other JOSE implementations.

## Installation
### NuGet 
not yet

### Manual
Grab source and compile yourself. 

## Usage
### Creating Plaintext (unprotected) Tokens

	string payload = @"{""hello"" : ""world""}";

	string token = JoseRT.Jwt.Encode(payload, JwsAlgorithm.None, null);

### Creating signed Tokens
#### HS256, HS384 and HS512 family
HS256, HS384, HS512 signatures require `byte[]` array key of corresponding length

    var secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

    string payload = @"{""hello"" : ""world""}";

    string token = JoseRT.Jwt.Encode(payload, JwsAlgorithm.HS256, secretKey);

#### RS256, RS384 and RS512 family
RS256, RS384, RS512 signatures require `CryptographicKey` private key of corresponding length. `JoseRT` provides convenient helpers to load RSA keys from commonly
used PEM encoded formats. See [Obtaining keys](#obtaining-keys) section for details.

	
	string payload = @"{""hello"" : ""world""}";

	string privateKey=
	@"-----BEGIN PRIVATE KEY-----
	MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALx97GSHCGkevvUS
	sXMscNd+08MjO8BbkrzzlDuokJzVvQQprSEFYCO1ojp1UheAImeQvMe1wAWrGNfb
	Fw34jQCSkv8liWLh5aHqHPrU8DTgKsL+XjHGaMwsg8y68pEmZrpyV/N49yXKlh3C
	1PLnFJrTmZq0PHLqOXINNvMWFv7jAgMBAAECgYEAsYc0RzY7AK7ZkX7KrLw1h3FH
	R2n+09wrp1UOzuWjVmOkw6/xBMHIW7mtkrt+1u1y+fIDK2GN+oi8PEl4PEtVmI8L
	jaExLu5fsp/Z+BbHfcs4L5So9pdGZn5Dhfh606LWRZ0qqSjdtXitpNMrjx736+Jt
	J6/kHlCdmYDyThtljbECQQDoDDAznyi6Yl2T+taoi2VcCP7wFAIYf3Mu6nqiEBhc
	p1lVOuWjyR+mBU8+o6hDs40oVAOdpCdqtDJ3ppWABKKZAkEAz/LIq8Uwq8ephNwn
	WOSuhkjUz+O01v74GHyS6tc7WGckFR7JS1cughXlRRq7hD1z1dhTYq0W2g4Yrujf
	GFTW2wJBAIwtQLkOfqYJYgpQz3fFrZdpf8g77gAqjcRbtXVNT8o49gg8qhjFGK9M
	KdDnQHCVeMJR7lU+oukcrhgFs+4/3pECQBcvX5ZfPwT4Fvt8PFrZ7GeGeUvQfJo4
	BVtdkFfktXYu0cQVEaZ3yvSwEkb5Kw0ceOzP2MQ4vkKDrdbamf0xgF8CQFiz2P8h
	Vq/Q3fFKCWamZ1olx08zo4x4y2kYKO275GSZabhiVoulVhUtRgi9BcPfW9kakqps
	wEe4//EeSbl38Bk=
	-----END PRIVATE KEY-----"

	
	string token = JoseRT.Jwt.Encode(payload, JwsAlgorithm.RS512, JoseRT.Rsa.PrivateKey.Load(privateKey));


#### ES256, ES384 and ES512  family
ES256, ES384, ES512 ECDSA signatures requires `CryptographicKey` private elliptic curve key of corresponding length. 
`JoseRT` provides convenient helpers to use raw key material (x,y) and d. See [Obtaining keys](#obtaining-keys) section for details.

    string json = @"{""hello"": ""world""}";

    byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
    byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
    byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

    var privateKey= JoseRT.Ecc.PrivateKey.New(x, y, d);    

    string token = JoseRT.Jwt.Encode(json, JwsAlgorithm.ES256, privateKey);


### Verifying and Decoding Tokens
Decoding json web tokens is fully symmetric to creating signed or encrypted tokens:

**HS256, HS384, HS512** signatures expecting `byte[]` array key

```cs
string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Fmz3PLVfv-ySl4IJ.LMZpXMDoBIll5yuEs81Bws2-iUUaBSpucJPL-GtDKXkPhFpJmES2T136Vd8xzvp-3JW-fvpRZtlhluqGHjywPctol71Zuz9uFQjuejIU4axA_XiAy-BadbRUm1-25FRT30WtrrxKltSkulmIS5N-Nsi_zmCz5xicB1ZnzneRXGaXY4B444_IHxGBIS_wdurPAN0OEGw4xIi2DAD1Ikc99a90L7rUZfbHNg_iTBr-OshZqDbR6C5KhmMgk5KqDJEN8Ik-Yw.Jbk8ZmO901fqECYVPKOAzg";

byte[] secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

string json = JoseRT.Jwt.Decode(token, secretKey);
```


### Obtaining keys
`Windows.Security.Cryptography` allows to import keys from bunch of different formats, but do not support commonly used PEM encoded formats out of box. 
To simplify integration and keys exchange between WinRT and other platforms, `JoseRT` provides set of helpers to import PEM encoded keys or other formats.

#### RSA keys
`JoseRT.Rsa.PublicKey.Load(string)` imports `CryptographicKey` from PEM encoded public key formats

##### PKCS#1 RSA Public Key

	-----BEGIN RSA PUBLIC KEY-----
	MIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmS
	tuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1
	MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXob
	DPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9Rra
	ShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXI
	khvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI
	2QIDAQAB
	-----END RSA PUBLIC KEY-----

##### X509 Public Subject key info
Can be obtained from certificate via `openssl x509 -inform PEM -in certificate.cer -outform PEM -pubkey -noout > public.key`

	-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmS
	tuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1
	MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXob
	DPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9Rra
	ShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXI
	khvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI
	2QIDAQAB
	-----END PUBLIC KEY-----

`JoseRT.Rsa.PrivateKey.Load(string)` imports `CryptographicKey` from PEM encoded private key formats

##### PKCS#1 RSA Private Key without password protection
Can be obtained from .p12 via `openssl pkcs12 -in keys.p12 -nocerts -out privateKey.pem` and then `openssl.exe rsa -in privateKey.pem -out privateKey.pem` to remove
password protection.

	-----BEGIN RSA PRIVATE KEY-----
	MIICXQIBAAKBgQC8fexkhwhpHr71ErFzLHDXftPDIzvAW5K885Q7qJCc1b0EKa0h
	BWAjtaI6dVIXgCJnkLzHtcAFqxjX2xcN+I0AkpL/JYli4eWh6hz61PA04CrC/l4x
	xmjMLIPMuvKRJma6clfzePclypYdwtTy5xSa05matDxy6jlyDTbzFhb+4wIDAQAB
	AoGBALGHNEc2OwCu2ZF+yqy8NYdxR0dp/tPcK6dVDs7lo1ZjpMOv8QTByFu5rZK7
	ftbtcvnyAythjfqIvDxJeDxLVZiPC42hMS7uX7Kf2fgWx33LOC+UqPaXRmZ+Q4X4
	etOi1kWdKqko3bV4raTTK48e9+vibSev5B5QnZmA8k4bZY2xAkEA6AwwM58oumJd
	k/rWqItlXAj+8BQCGH9zLup6ohAYXKdZVTrlo8kfpgVPPqOoQ7ONKFQDnaQnarQy
	d6aVgASimQJBAM/yyKvFMKvHqYTcJ1jkroZI1M/jtNb++Bh8kurXO1hnJBUeyUtX
	LoIV5UUau4Q9c9XYU2KtFtoOGK7o3xhU1tsCQQCMLUC5Dn6mCWIKUM93xa2XaX/I
	O+4AKo3EW7V1TU/KOPYIPKoYxRivTCnQ50BwlXjCUe5VPqLpHK4YBbPuP96RAkAX
	L1+WXz8E+Bb7fDxa2exnhnlL0HyaOAVbXZBX5LV2LtHEFRGmd8r0sBJG+SsNHHjs
	z9jEOL5Cg63W2pn9MYBfAkBYs9j/IVav0N3xSglmpmdaJcdPM6OMeMtpGCjtu+Rk
	mWm4YlaLpVYVLUYIvQXD31vZGpKqbMBHuP/xHkm5d/AZ
	-----END RSA PRIVATE KEY-----

##### PKCS#8 Raw RSA Private Key
Can be converted from PKCS#1 private key via `openssl pkcs8 -topk8 -inform PEM -outform PEM -in privateKey.pem -out privateKey.key -nocrypt`

	-----BEGIN PRIVATE KEY-----
	MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALx97GSHCGkevvUS
	sXMscNd+08MjO8BbkrzzlDuokJzVvQQprSEFYCO1ojp1UheAImeQvMe1wAWrGNfb
	Fw34jQCSkv8liWLh5aHqHPrU8DTgKsL+XjHGaMwsg8y68pEmZrpyV/N49yXKlh3C
	1PLnFJrTmZq0PHLqOXINNvMWFv7jAgMBAAECgYEAsYc0RzY7AK7ZkX7KrLw1h3FH
	R2n+09wrp1UOzuWjVmOkw6/xBMHIW7mtkrt+1u1y+fIDK2GN+oi8PEl4PEtVmI8L
	jaExLu5fsp/Z+BbHfcs4L5So9pdGZn5Dhfh606LWRZ0qqSjdtXitpNMrjx736+Jt
	J6/kHlCdmYDyThtljbECQQDoDDAznyi6Yl2T+taoi2VcCP7wFAIYf3Mu6nqiEBhc
	p1lVOuWjyR+mBU8+o6hDs40oVAOdpCdqtDJ3ppWABKKZAkEAz/LIq8Uwq8ephNwn
	WOSuhkjUz+O01v74GHyS6tc7WGckFR7JS1cughXlRRq7hD1z1dhTYq0W2g4Yrujf
	GFTW2wJBAIwtQLkOfqYJYgpQz3fFrZdpf8g77gAqjcRbtXVNT8o49gg8qhjFGK9M
	KdDnQHCVeMJR7lU+oukcrhgFs+4/3pECQBcvX5ZfPwT4Fvt8PFrZ7GeGeUvQfJo4
	BVtdkFfktXYu0cQVEaZ3yvSwEkb5Kw0ceOzP2MQ4vkKDrdbamf0xgF8CQFiz2P8h
	Vq/Q3fFKCWamZ1olx08zo4x4y2kYKO275GSZabhiVoulVhUtRgi9BcPfW9kakqps
	wEe4//EeSbl38Bk=
	-----END PRIVATE KEY-----

#### Elliptic Curve keys
`JoseRT` provides helpers to construct private or public ECC keys from raw key material: (X,Y) and D, represented as `byte[]` arrays, elliptic curve will be automatically
determined by size of provided material. Supported are NIST P-256, P-384 and P-521 curves.

##### Private Key
Can be constructed by calling `JoseRT.Ecc.PrivateKey.New(x, y, d)`

    byte[] x = { 0, 248, 73, 203, 53, 184, 34, 69, 111, 217, 230, 255, 108, 212, 241, 229, 95, 239, 93, 131, 100, 37, 86, 152, 87, 98, 170, 43, 25, 35, 80, 137, 62, 112, 197, 113, 138, 116, 114, 55, 165, 128, 8, 139, 148, 237, 109, 121, 40, 205, 3, 61, 127, 28, 195, 58, 43, 228, 224, 228, 82, 224, 219, 148, 204, 96 };
    byte[] y = { 0, 60, 71, 97, 112, 106, 35, 121, 80, 182, 20, 167, 143, 8, 246, 108, 234, 160, 193, 10, 3, 148, 45, 11, 58, 177, 190, 172, 26, 178, 188, 240, 91, 25, 67, 79, 64, 241, 203, 65, 223, 218, 12, 227, 82, 178, 66, 160, 19, 194, 217, 172, 61, 250, 23, 78, 218, 130, 160, 105, 216, 208, 235, 124, 46, 32 };
    byte[] d = { 0, 222, 129, 9, 133, 207, 123, 116, 176, 83, 95, 169, 29, 121, 160, 137, 22, 21, 176, 59, 203, 129, 62, 111, 19, 78, 14, 174, 20, 211, 56, 160, 83, 42, 74, 219, 208, 39, 231, 33, 84, 114, 71, 106, 109, 161, 116, 243, 166, 146, 252, 231, 137, 228, 99, 149, 152, 123, 201, 157, 155, 131, 181, 106, 179, 112 };

    var privateEccKey=JoseRT.Ecc.PrivateKey.New(x, y, d);

##### Public Key
Can be constructed by calling `JoseRT.Ecc.PublicKey.New(x, y)`

    byte[] x = { 0, 248, 73, 203, 53, 184, 34, 69, 111, 217, 230, 255, 108, 212, 241, 229, 95, 239, 93, 131, 100, 37, 86, 152, 87, 98, 170, 43, 25, 35, 80, 137, 62, 112, 197, 113, 138, 116, 114, 55, 165, 128, 8, 139, 148, 237, 109, 121, 40, 205, 3, 61, 127, 28, 195, 58, 43, 228, 224, 228, 82, 224, 219, 148, 204, 96 };
    byte[] y = { 0, 60, 71, 97, 112, 106, 35, 121, 80, 182, 20, 167, 143, 8, 246, 108, 234, 160, 193, 10, 3, 148, 45, 11, 58, 177, 190, 172, 26, 178, 188, 240, 91, 25, 67, 79, 64, 241, 203, 65, 223, 218, 12, 227, 82, 178, 66, 160, 19, 194, 217, 172, 61, 250, 23, 78, 218, 130, 160, 105, 216, 208, 235, 124, 46, 32 };

    var publicEccKey=JoseRT.Ecc.PublicKey.New(x, y, d);

