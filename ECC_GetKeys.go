package go_crypto

/*
author:CNbluer
time: 2018.11.5
Email:gaozijian51@gmail.com
 */
import (
	"os"
	"encoding/pem"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
)

//得到秘钥对，保存到文件中，适合长期使用
// 输入私钥和公钥所需存放路径
func Ecc_Getkeys_savetofile(privatePath,publicPath string)  {
	//第一个参数所需选择一条曲线，目前调用以太坊接口只能使用256这条曲线
	privateKey,_:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	fp,err:=os.Create(privatePath)
	if err!=nil {
		panic(err)
	}
	defer fp.Close()
	//通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	x509_privateKey,err:=x509.MarshalECPrivateKey(privateKey)
	if err!=nil {
		panic(err)
	}
	//将私钥字符串设置到pem格式块中
	pem_privatekey:=pem.Block{
		Type:"CNbluer Private Key",
		Bytes:x509_privateKey,
	}
	//通过pem将设置好的数据进行编码，并保存到磁盘中
	err=pem.Encode(fp,&pem_privatekey)
	if err!=nil {
		panic(err)
	}

	//同理得到公钥
	fp,err=os.Create(publicPath)
	if err!=nil {
		panic(err)
	}
	defer fp.Close()
	x509_publickey,err:=x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err!=nil {
		panic(err)
	}
	pem_publickey:=pem.Block{
		Type:"CNbluer Publickey Key",
		Bytes:x509_publickey,
	}
	err=pem.Encode(fp,&pem_publickey)
	if err!=nil {
		panic(err)
	}


}

//不保存到文件中，适合一次性使用
func Ecc_Getkeys_nosave()(privatekey *ecdsa.PrivateKey,publickey *ecdsa.PublicKey)  {
	//仍然选择曲线p256
	privatekey,_=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	publickey=&privatekey.PublicKey
	return privatekey,publickey
}


