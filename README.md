# WinRT component implementation of Javascript Object Signing and Encryption (JOSE) and JSON Web Token (JWT)

##Credits

## Supported JWA algorithms

**Signing**
- HMAC signatures with HS256, HS384 and HS512.

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

### Verifying and Decoding Tokens
Decoding json web tokens is fully symmetric to creating signed or encrypted tokens:

**HS256, HS384, HS512** signatures expecting `byte[]` array key

    string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Fmz3PLVfv-ySl4IJ.LMZpXMDoBIll5yuEs81Bws2-iUUaBSpucJPL-GtDKXkPhFpJmES2T136Vd8xzvp-3JW-fvpRZtlhluqGHjywPctol71Zuz9uFQjuejIU4axA_XiAy-BadbRUm1-25FRT30WtrrxKltSkulmIS5N-Nsi_zmCz5xicB1ZnzneRXGaXY4B444_IHxGBIS_wdurPAN0OEGw4xIi2DAD1Ikc99a90L7rUZfbHNg_iTBr-OshZqDbR6C5KhmMgk5KqDJEN8Ik-Yw.Jbk8ZmO901fqECYVPKOAzg";

    byte[] secretKey = new byte[]{164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234};

    string json = JoseRT.Jwt.Decode(token, secretKey);




