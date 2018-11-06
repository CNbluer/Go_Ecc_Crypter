package go_crypto

/*
author:CNbluer
time: 2018.11.5
Email:gaozijian51@gmail.com
 */
import (
	"os"
	"encoding/pem"
	"crypto/x509"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
)

//加密，公钥可以接收如下三种类型的数据
//1、公钥所在pem文件路径 2、拷贝下来的切片类型公钥 3、原生的*ecdsa.Publickey类型
func Ecc_Encrypt(publicKey interface{},plainText []byte)[]byte {
	//判断接受到的是哪种类型数据，根据类型选择不同的方法
	switch publicKey.(type) {
	case string:
		//文件路径
		fp, err := os.Open(publicKey.(string))
		if err != nil {
			panic(err)
		}
		defer fp.Close()
		fileinfo, err := fp.Stat()
		if err != nil {
			panic(err)
		}
		//这一块我们是把整个文件中的内容读取下来保存到buf中
		buf := make([]byte, fileinfo.Size())
		fp.Read(buf)
		//pem解码
		block, _ := pem.Decode(buf)
		//x509解码
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		//调用以太坊中的函数，需要先将go标准库中的公钥类型封装成以太坊中通用的类型
		eth_publickey := ImportECDSAPublic(pub.(*ecdsa.PublicKey))
		//封装完毕
		cipherText, err := Encrypt(rand.Reader, eth_publickey, plainText, nil, nil)
		if err != nil {
			panic(err)
		}
		return cipherText

	case *ecdsa.PublicKey:
		//原生公钥类型

		eth_publickey := ImportECDSAPublic(publicKey.(*ecdsa.PublicKey))
		cipherText, err := Encrypt(rand.Reader, eth_publickey, plainText, nil, nil)
		if err != nil {
			panic(err)
		}
		return cipherText

	case []byte:
		block,_:=pem.Decode(publicKey.([]byte))
		fmt.Println(string(block.Bytes))
		pub, _:= x509.ParsePKIXPublicKey(block.Bytes)

		eth_publickey := ImportECDSAPublic(pub.(*ecdsa.PublicKey))
		cipherText, err := Encrypt(rand.Reader, eth_publickey, plainText, nil, nil)
		if err != nil {
			panic(err)
		}
		return cipherText

	default:
		panic("可以接收如下三种类型的数据" + "\n" +
			"1、公钥所在pem文件路径 2、拷贝下来的切片类型公钥 " +
			"3、原生的*ecdsa.Publickey类型，" + "\n" +
			"请检查是否符合")
	}
}


//加密，公钥可以接收如下三种类型的数据
//1、私钥所在pem文件路径 2、拷贝下来的切片类型私钥 3、原生的*ecdsa.Privatekey类型
func Ecc_Decrypt(privateKey interface{},cipherText []byte)[]byte {
	//判断接受到的是哪种类型数据，根据类型选择不同的方法
	switch privateKey.(type) {
	case string:
		//文件路径
		fp, err := os.Open(privateKey.(string))
		if err != nil {
			panic(err)
		}
		defer fp.Close()
		fileinfo, err := fp.Stat()
		if err != nil {
			panic(err)
		}
		//这一块我们是把整个文件中的内容读取下来保存到buf中
		buf := make([]byte, fileinfo.Size())
		fp.Read(buf)
		//pem解码
		block, _ := pem.Decode(buf)
		//x509解码
		pub, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		//调用以太坊中的函数，需要先将go标准库中的私钥类型封装成以太坊中通用的类型
		eth_privatekey := ImportECDSA(pub)
		//封装完毕
		m,err:=eth_privatekey.Decrypt(cipherText,nil,nil)
		if err != nil {
			panic(err)
		}
		return m

	case *ecdsa.PrivateKey:
		//原生私钥类型
		eth_privatekey := ImportECDSA(privateKey.(*ecdsa.PrivateKey))
		m,err:=eth_privatekey.Decrypt(cipherText,nil,nil)
		if err != nil {
			panic(err)
		}
		return m

	case []byte:
		block,_:=pem.Decode(privateKey.([]byte))
		pub, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		eth_privatekey := ImportECDSA(pub)
		m,err:=eth_privatekey.Decrypt(cipherText,nil,nil)
		if err != nil {
			panic(err)
		}
		return m

	default:
		panic("可以接收如下三种类型的数据" + "\n" +
			"1、公钥所在pem文件路径 2、拷贝下来的切片类型公钥 " +
			"3、原生的*ecdsa.Publickey类型，" + "\n" +
			"请检查是否符合")
	}
}