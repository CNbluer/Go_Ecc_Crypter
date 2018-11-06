# Go_Ecc_Crypter

### Background

go标准包里因为种种不明原因，对椭圆形加密只给出了数字签名的函数，却不能拿来进行加密解密。在网上查了很多资料，大多都是调用了椭圆形加密的数字签名函数，没有给出解决方法的。

只有一篇文章提到了以太坊中有给出了椭圆加密解密的方法，于是我进行了二次封装，取出以太坊中关键性的一些代码，融合上人性化的设计，秘钥可以是多种形态，程序也可以自行识别。

****

### Introduction

Go_Ecc_Crypter包给出了解决方案，可以直接调用进行椭圆曲线加密解密。

一共四个go文件，其中ecies.go 和 params.go是以太坊中关于椭圆加密的一些方法，

ECC_GetKeys.go提供了获得获得秘钥对的两种方法，一种可以保存到文件，作为长期使用，另一种作为一次性使用，不保存到文件。

ECC_Crypter.go提供了加密和解密的封装，抛弃了传统的单一传入密钥的方法，这里进行了类型选择和断言，用户可以传入复制粘贴来的密钥，也可以传入秘钥所在文件路径，也可以传入一次性生成的原生秘钥。

****

### User

用户可调用函数极其功能：

```go
func Ecc_Getkeys_savetofile(privatePath,publicPath string)
//传入私钥和公钥所需保存的路径
//即可在路径生成一堆秘钥，可作为长期使用


func Ecc_Getkeys_nosave()(privatekey *ecdsa.PrivateKey,publickey *ecdsa.PublicKey)
//返回两个原生参数，不保存到本地，可一次性使用


func Ecc_Encrypt(publicKey interface{},plainText []byte)[]byte
//椭圆形曲线加密
//人性化设计，可以接收如下三种类型的公钥数据
//1、公钥所在pem文件路径 2、拷贝下来的切片类型公钥 3、原生的*ecdsa.Publickey类型
//返回密文 

Ecc_Decrypt(privateKey interface{},cipherText []byte)[]byte
//椭圆形曲线解密
//同样可以接收如上三种类型数据，返回解密后的数据
```

## 缺陷和展望

目前只能支持椭圆曲线中的p256算法，其他暂不支持，希望大家能一起补充、完善。





