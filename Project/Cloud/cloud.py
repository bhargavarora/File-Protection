import struct
import pprint
import os
import sys
import datetime
import calendar
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random

# Function to Get File Name
def getFileName(fName,op):
	path = "/root/Desktop/LakshmanArora-cs6903s17project2/LakshmanArora-Files/Project/Cloud"
	if(op == 1):
		pprint.pprint("Please enter valid file name")
		fName = raw_input()
		# Verify if File Exists
		if os.path.isfile(path + "/" + fName):
			return fName
		pprint.pprint("Incorrect File Name")
		sys.exit(0)
		return
	elif(op == 2):
		if os.path.isfile(path + "/" + fName):
			return fName
		pprint.pprint("Incorrect File Name")
		sys.exit(0)
		return
	return

# Function to Print File Contents
def printFile(fName):
	with open(fName, 'rb') as f:
		print f.read()
	return

# Function to Calculate File Hash
def getFileHash(fName):
	with open(fName,'rb') as f:
		buf = f.read()
	fhash = SHA256.new(buf)
	return fhash

# Function to Get Private Key
def getPrivateKey(privateKey):
	myPrivateKey = RSA.importKey(open(privateKey).read())
	return myPrivateKey

# Function to Calculate Digital Signature
def getDigitalSignature(fHash,privateKey):
	signer = PKCS1_v1_5.new(privateKey)
	signature = signer.sign(fHash)
	return signature

# Function to Append Message with Session Key to File 
def appendToFile(fName,message):
	apndMssg = "===|+|===" + str(message)
	with open(fName, 'a') as f:
		f.write(apndMssg)
	return fName

# Function to generate expiresBy Timestamp
def getExpiry():
	fDate = str(datetime.datetime.now() + datetime.timedelta(minutes=1))
	return fDate

# Function to Append Signature to File
def addSignatureTimestamp(fName,signature,expiresBy,delimiter='===|+|==='):
	with open(fName,'rb') as f:
		buf = f.read()
	cfName =fName +".tmp"
	with open(cfName,'w+') as f1:
		f1.write(buf)
		f1.write(delimiter)
		f1.write(str(expiresBy))
		f1.write(delimiter)
		f1.write(signature)
	return cfName

# Function to Encrypt File Contents
def fileEncrypt(fName,sessionKey):
	# Set encrypted file name
	cfName = fName + ".enc"

	# Check if encrypted file name already used. 
	# If Yes, Delete and continue
	if os.path.isfile(cfName):
		os.remove(cfName)

	cSize = 64 * 1024
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(sessionKey, AES.MODE_CBC, iv)
	fSize = os.path.getsize(fName)

	with open(fName,'rb') as rFile:
		with open(cfName,'wb') as oFile:
			oFile.write(struct.pack('<Q',fSize))
			oFile.write(iv)

			while True:
				chunk = rFile.read(cSize)
				if (len(chunk) == 0):
					break
				elif ((len(chunk)%16) != 0):
					chunk += ' ' * (16 - len(chunk)%16)

				cipherText = cipher.encrypt(chunk)
				oFile.write(cipherText)
	return cfName

# Function to Get Publick Key
def getPublicKey(publicKey):
	cPublicKey = RSA.importKey(open(publicKey).read())
	return cPublicKey

# Function to Encrypt Session Key
def sessionKeyEncrypt(sessionKey,cPublicKey):
	cipher = PKCS1_OAEP.new(cPublicKey)
	cipherSessionKey = cipher.encrypt(sessionKey)
	return cipherSessionKey

# Function to SendFile
def sendF(fName):
	os.system("cp " + fName + " ./../Client")
	return 0

# Function to Decrypt Session Key
def sessionKeyDecrypt(privateKey,cSessionKey):
	cipher = PKCS1_OAEP.new(privateKey)
	sessionKey = cipher.decrypt(cSessionKey)
	return sessionKey

# Function to Split Message
def splitMessage(fName,delimiter='===|+|==='):
	with open(fName,'r+') as f:
		buf = f.read()
	z = buf.split(delimiter)
	f.close()
	with open(fName,'w') as f1:
		f1.write(z[0])
	if (len(z)>2):
		return fName,z[1],z[2]
	return fName,z[1]

# Function to Decrypt File Contents
def fileDecrypt(fName, sessionKey):
	chunkSize = 24*1024
	with open(fName,'rb') as f:
		size = struct.unpack('<Q',f.read(struct.calcsize('Q')))[0]
		iv = f.read(16)
		decrypt = AES.new(sessionKey, AES.MODE_CBC, iv)

		decName = fName + ".tmp"
		with open(decName,'wb') as f1:
			while  True:
				chunk = f.read(chunkSize)
				if (len(chunk) == 0):
					break
				f1.write(decrypt.decrypt(chunk))
			f1.truncate(size)
	return decName

# Function to Check ExpiresBy TimeStamp
def checkExpiry(expiresBy):
	expBy = datetime.datetime.strptime(expiresBy, "%Y-%m-%d %H:%M:%S.%f")
	cDate = datetime.datetime.now()
	if cDate < expBy:
		return True
	return False

# Function to Verify Signature
def verifySignature(fName,signature,publicKey):
	with open(fName,'rb') as f:
		buf = f.read()
	fhash = SHA256.new(buf)
	verifier = PKCS1_v1_5.new(publicKey)
	isValid = verifier.verify(fhash,signature)
	return isValid

# Function to Write Decrypted File Contents to File
def writeFile(fName):
	name = fName.split('.')
	ofName = name[0] 
	with open(fName,'r') as f:
		with  open(ofName,'w+') as f1:
			for line in f:
				f1.write(line)
	return ofName

# Function to Send a File to Client; Encrypts and then sends
def sendFileCloud(identifier):
	pprint.pprint("----------------------------------------------------------------------------------------------------------------------------------------------")
	keyFileName = "privateKey_" + identifier + ".pem"
	
	path = "/root/Desktop/LakshmanArora-cs6903s17project2/LakshmanArora-Files/Project/Cloud"
	os.chdir("./../Cloud")

	# Step 1 - Check (or) Generate Keys
	if not os.path.isfile(path + "/" + keyFileName):
			pprint.pprint("KeyPair Unavailable !")
			sys.exit(0)

	# Step 2 - Get & Verify File Name
	fName = getFileName(' ',op=1)

	# Step 3 - Hash File Contents
	fHash = getFileHash(fName)

	# Step 4 - Get Private Key
	myPrivateKey = getPrivateKey(keyFileName)

	# Step 5 - Get Digital Signature
	signature = getDigitalSignature(fHash,myPrivateKey)

	#Step 6 - Get expireBy Timestamp
	expiresBy = getExpiry()

	# Step 6 - Append Digital Signature 
	fName = addSignatureTimestamp(fName,signature,expiresBy)

	# Step 7 - Generate one-time session key - 16 Bytes 
	sessionKey = os.urandom(16)
	
	# Step 8 - Encrypt File Contents with Session Key; Return cipher File Name
	cfName = fileEncrypt(fName,sessionKey)

	# Step 9 - Get PublicKey of the Cloud
	xyz = "publicKey_client_01.pem"
	cPublicKey = getPublicKey(xyz)
	
	# Step 10 - Encrypt one-time session key with PublicKey of Cloud
	cipherSessionKey = sessionKeyEncrypt(sessionKey,cPublicKey)

	# Step 11 - Append encrypted one-time session key
	cfName = appendToFile(cfName,cipherSessionKey)

	# Step 12 - Send Encrypted File to Cloud
	sendF(cfName)

	os.system("rm "+ fName )
	os.system("rm "+ cfName)

	return cfName

# Function to Get a File from Client; Decrypts on Recieveing 
def getFile(identifier,fname):
	keyFileName = "privateKey_" + identifier + ".pem"

	path = "/root/Desktop/LakshmanArora-cs6903s17project2/LakshmanArora-Files/Project/Cloud"
	os.chdir("./../Cloud")

	# Step 1 - Check (or) Generate Keys
	if not os.path.isfile(path + "/" + keyFileName):
			pprint.pprint("KeyPair Unavailable. Will exit now")
			sys.exit(0)


	# Step 2 - Get File Name
	cfName = getFileName(fname,op=2)

	# Step 3 - Split Contents to retrieve Session Key
	cfName, cSessionKey = splitMessage(cfName)

	# Step 4 - Get PrivateKey
	myPrivateKey = getPrivateKey(keyFileName)

	# Step 5 - Decrypt Session Key
	sessionKey = sessionKeyDecrypt(myPrivateKey,cSessionKey)

	# Step 6 - Decrypt Message with Session Key 
	fName = fileDecrypt(cfName,sessionKey)

	# Step 7 - Split Message to retrieve Digital Signature, TimeStamp
	sfName, expiresBy, signature = splitMessage(fName)

	# Step 8 - Check if message is expired
	isValid = checkExpiry(expiresBy)
	if not isValid:
		pprint.pprint("Error - Message Expired - Possible Replay Attack!!!")
		sys.exit(0)

	# Step 9 - Get Public Key
	publicKey = "publicKey_client_01.pem"
	publicKey = getPublicKey(publicKey)

	# Step 10 - Verify Signature
	isValid = verifySignature(fName,signature,publicKey)
	if (not isValid):
		pprint.pprint("Error - Integrity Check Failed - Digital Signature does not match !!!!")
		sys.exit(0)

	# Step 11 - Write Decrypted Message to File; Return Decrypted File Name 
	ofName = writeFile(fName)

	os.system("rm " + fName)
	os.system("rm " + cfName)

	pprint.pprint("----------------------------------------------------------------------------------------------------------------------------------------------")
	pprint.pprint("Notification from Cloud - All checks Passed on receival  !!! - Checked for Confidentiality, Integrity, Anti-Replay")
	pprint.pprint("----------------------------------------------------------------------------------------------------------------------------------------------")
	return 


if __name__ == "__main__":
	pprint.pprint("Hello World - Cloud is Running")
	identifier = "cloud"
	pprint.pprint("Welcome Client! Choose one option")
	pprint.pprint(" 1. Upload a File")
	pprint.pprint(" 2. Download a File")
	pprint.pprint("Please enter one option - 1 (or) 2")
	ip = raw_input()
	if (int(ip) == 1):
		sendFile(identifier)
	elif (int(ip) == 2):
		getFile(identifier)
	else:
		pprint.pprint("Illegal Option")
		sys.exit(0)



