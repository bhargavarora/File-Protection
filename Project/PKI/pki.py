import pprint
import sys
import os


def generateKeyPair(identifier):
	privateKeyName = "privateKey_" + identifier + ".pem"
	publicKeyName = "publicKey_" + identifier +".pem"

	# Generate RSA PrivateKey using OpenSSL
	os.system("openssl genrsa -out " + privateKeyName + " 2048")

	# Generate RSA PublicKey using OpenSSL
	os.system("openssl rsa -in "+ privateKeyName +" -outform PEM -pubout -out "+ publicKeyName)
 
	sendKeyPair(identifier, privateKeyName, publicKeyName)
	return 0

def sendKeyPair(identifier,privateKeyName,publicKeyName):
	if (identifier == "cloud"):
		# Copy PrivateKeyFile to Directory of Sender
		os.system("cp " + privateKeyName + " ./../Cloud")
		# Copy File PublicKey to Directory of Sender
		os.system("cp " + publicKeyName + " ./../Cloud" )
		# Remove File PrivateKey from PKI Directory
		os.system("rm " + privateKeyName)
	elif (identifier == "client_01"):
		# Copy PrivateKeyFile to Directory of Sender
		os.system("cp " + privateKeyName + " ./../Client")
		# Copy File PublicKey to Directory of Sender
		os.system("cp " + publicKeyName + " ./../Client" )
		# Remove File PrivateKey from PKI Directory
		os.system("rm " + privateKeyName)
	return 0

def exchangePublicKeys(identifier1, identifier2):
	publicKeyName1 = "publicKey_" + identifier1 +".pem"
	publicKeyName2 = "publicKey_" + identifier2 +".pem"
	os.system("cp "+ publicKeyName1 + " ./../Client")
	os.system("cp "+ publicKeyName2 + " ./../Cloud")
	return 0


if __name__ == "__main__":
	generateKeyPair("cloud")
	generateKeyPair("client_01")
	exchangePublicKeys("cloud","client_01")
	pprint.pprint("Keys successfully generated !!!")

