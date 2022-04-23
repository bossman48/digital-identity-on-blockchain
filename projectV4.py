# Python program to create Blockchain

#pip install pycryptodomex

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# For timestamp
import datetime

# Calculating the hash
# in order to add digital
# fingerprints to the blocks
import hashlib

# To store data
# in our blockchain
import json

""" Flask is for creating the web
# app and jsonify is for
# displaying the blockchain
pip install Flask"""
from flask import Flask, jsonify,request


"""import rsa to generate public and private key
pip install rsa
"""
import rsa

import random

class checkClass:
	byteResponse=b''

class Blockchain:

	# This function is created
	# to create the very first
	# block and set its hash to "0"
	def __init__(self):
		self.chain = []
		self.create_block(proof=1, previous_hash='0',publicKey='')

	# This function is created
	# to add further blocks
	# into the chain
	def create_block(self, proof, previous_hash,publicKey):
		block = {'index': len(self.chain) + 1,
				'timestamp': str(datetime.datetime.now()),
				'proof': proof,
				'previous_hash': previous_hash,
                'publicKey':publicKey}
		self.chain.append(block)
		return block

	# This function is created
	# to display the previous block
	def print_previous_block(self):
		return self.chain[-1]

	# This is the function for proof of work
	# and used to successfully mine the block
	def proof_of_work(self, previous_proof):
		new_proof = 1
		check_proof = False

		while check_proof is False:
			hash_operation = hashlib.sha256(
				str(new_proof**2 - previous_proof**2).encode()).hexdigest()
			if hash_operation[:5] == '00000':
				check_proof = True
			else:
				new_proof += 1

		return new_proof

	def hash(self, block):
		encoded_block = json.dumps(block, sort_keys=True).encode()
		return hashlib.sha256(encoded_block).hexdigest()

	def getBlockInfo(self,index):
		return self.chain[index]

	def chain_valid(self, chain):
		previous_block = chain[0]
		block_index = 1

		while block_index < len(chain):
			block = chain[block_index]
			if block['previous_hash'] != self.hash(previous_block):
				return False

			previous_proof = previous_block['proof']
			proof = block['proof']
			hash_operation = hashlib.sha256(
				str(proof**2 - previous_proof**2).encode()).hexdigest()

			if hash_operation[:5] != '00000':
				return False
			previous_block = block
			block_index += 1

		return True


# Creating the Web
# App using flask
app = Flask(__name__)


# Create the object
# of the class blockchain
blockchain = Blockchain()

randomNumberForServiceProviderChecking=0
checkClass = checkClass()

"""
curl example is below
sudo apt  install curl
curl -X POST -H "Content-type: application/json" -d "{\"firstName\" : \"John\", \"lastName\" : \"Smith\"}" "127.0.0.1:5000/post_json"
"""
@app.route('/post_json', methods=['POST'])
def process_json():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        json = request.json
        return json["firstName"]
    else:
        return 'Content-Type not supported!'

#print(blockchain.getBlockInfo(1));
# Mining a new block
@app.route('/mine_block', methods=['GET'])
def mine_block():
	previous_block = blockchain.print_previous_block()
	previous_proof = previous_block['proof']
	proof = blockchain.proof_of_work(previous_proof)
	previous_hash = blockchain.hash(previous_block)
	block = blockchain.create_block(proof, previous_hash,"")

	response = {'message': 'A block is MINED',
				'index': block['index'],
				'timestamp': block['timestamp'],
				'proof': block['proof'],
				'previous_hash': block['previous_hash']}

	return jsonify(response), 200

@app.route('/addUserToBlockchain', methods=['POST'])
def addUserToBlockchain():
	content_type = request.headers.get('Content-Type')
	if (content_type == 'application/json'):
		json = request.json
        #return json["firstName"]
	else:
		return 'Content-Type not supported!'


	previous_block = blockchain.print_previous_block()
	previous_proof = previous_block['proof']
	proof = blockchain.proof_of_work(previous_proof)
	previous_hash = blockchain.hash(previous_block)
	block = blockchain.create_block(proof, previous_hash,json["publicKey"])

	response = {'message': 'User informations are added to blockchain',
				'index': block['index'],
				'timestamp': block['timestamp'],
				'proof': block['proof'],
				'previous_hash': block['previous_hash'],
                'publicKey': block['publicKey']}

	return jsonify(response), 200

@app.route('/toServiceProvider', methods=['POST'])
def toServiceProvider():
	content_type = request.headers.get('Content-Type')
	if (content_type == 'application/json'):
		json = request.json
        #return json["firstName"]
	else:
		return 'Content-Type not supported!'

	block = blockchain.getBlockInfo(int(json["index"])-1)
	#print(list(block["privateUid"]))

	if(1):
		#print("asd")
		randomNumberForServiceProviderChecking=random.randint(0,100000000000)
		privateUid=int(randomNumberForServiceProviderChecking)
		message = str(privateUid)
		message = message.encode()
		publicKey = RSA.import_key(block['publicKey'])
		cipher = PKCS1_OAEP.new(publicKey)
		encryptedMessage = cipher.encrypt(message);
		checkClass.byteResponse=message;
		print("Random Number for check the user private key:" ,message)
		response = {'encryptedMessage':list(encryptedMessage)} 
	else:
		response = {'message':'Rejected'}

	return jsonify(response), 200



@app.route('/toServiceGenerateRandomNumber', methods=['POST'])
def toServiceProviderRandomNumber():
	content_type = request.headers.get('Content-Type')
	if (content_type == 'application/json'):
		json = request.json
        #return json["firstName"]
	else:
		return 'Content-Type not supported!'

	privateKeyStr = json["privateKey"]
	#print("Private Key:" ,privateKeyStr)
	privatekey = RSA.import_key(privateKeyStr)
	cipher = PKCS1_OAEP.new(privatekey)
	decryptedMessage = cipher.decrypt(bytes(json["encryptedMessage"]))
	print("decryptedMessage:" ,decryptedMessage)

	response = {
		"decryptedMessage":str(decryptedMessage),
        "username":"osman"
	}

	return jsonify(response), 200

@app.route('/checkRandomNumberWithInformation', methods=['POST'])
def checkRandomNumberWithInformation():
	content_type = request.headers.get('Content-Type')
	if (content_type == 'application/json'):
		json = request.json
        #return json["firstName"]
	else:
		return 'Content-Type not supported!'

	decryptedMessage = json["decryptedMessage"]
	print("decryptedMessageType:" ,type(decryptedMessage))
	print("byteResponseType:" ,type(checkClass.byteResponse))
	print("decryptedMessage:" ,decryptedMessage)
	print("byteResponse:" ,checkClass.byteResponse)
	if(str(decryptedMessage)==str(checkClass.byteResponse)):
		response={
			"message":"Accept"
		}
	else:
		response={
			"message":"Reject"
		}
	

	return jsonify(response), 200



# Display blockchain in json format
@app.route('/get_chain', methods=['GET'])
def display_chain():

	response = {'chain': str(blockchain.chain),
				'length': len(blockchain.chain)}

	return jsonify(response), 200

# Check validity of blockchain
@app.route('/valid', methods=['GET'])
def valid():
	valid = blockchain.chain_valid(blockchain.chain)

	if valid:
		response = {'message': 'The Blockchain is valid.'}
	else:
		response = {'message': 'The Blockchain is not valid.'}
	return jsonify(response), 200


# Run the flask server locally
@app.route('/createKeys', methods=['GET'])
def createKeys():
	key = RSA.generate(2048)
	publicKey = key.publickey().exportKey("PEM")
	privateKey = key.exportKey("PEM")

    # this is the string that we will be encrypting
	message = "hello geeks"

	#this is for library
	message= bytes(message,"utf-8")
    # rsa.encrypt method is used to encrypt
    # string with public key string should be
    # encode to byte string before encryption
    # with encode method

	publicKeyStr=str(publicKey,"utf-8")
	publickey = RSA.import_key(publicKeyStr)
	cipher = PKCS1_OAEP.new(publickey)
	encryptedMessage = cipher.encrypt(message)
	print(encryptedMessage)
	print(str(encryptedMessage))
	print(list(encryptedMessage))
	print(bytes(list(encryptedMessage)))


	#key = RSA.import_key(open("private.pem").read())
	privateKeyStr=str(privateKey,"utf-8")
	privatekey = RSA.import_key(privateKeyStr)
	cipher = PKCS1_OAEP.new(privatekey)
	decryptedMessage = cipher.decrypt(bytes(list(encryptedMessage)))

	"""print("\noriginal string: ", message)
	print("public key string: ", publicKey)
	print("private key string: ", privateKey)"""

    # the encrypted message can be decrypted
    # with ras.decrypt method and private key
    # decrypt method returns encoded byte string,
    # use decode method to convert it to string
    # public key cannot be used for decryption
    #response = { 'message': str(message,"utf-8"), 'encryptMessage':list(encryptedMessage), 'decMessage':str(decryptedMessage), 'publicKey': str(publicKeyStr), 'privateKey': str(privateKeyStr)}
	
	response = { 'publicKey': str(publicKeyStr), 'privateKey': str(privateKeyStr)}
	return jsonify(response), 200





#for get user public key, private key and privateuid

@app.route('/getUserKeys', methods=['POST'])
def getUserKeys():

	content_type = request.headers.get('Content-Type')
	if (content_type == 'application/json'):
		json = request.json
        #return json["firstName"]
	else:
		return 'Content-Type not supported!'
	
	print("\noriginal json: ", json)
	print("\noriginal privateUid: ", json['privateUid'])
	key = RSA.generate(2048)
	publicKey = key.publickey().exportKey("PEM")
	privateKey = key.exportKey("PEM")

	publicKeyStr=str(publicKey,"utf-8")

	privateKeyStr=str(privateKey,"utf-8")
	privateUid=int(json['privateUid'])
	message = str(privateUid)
	message = message.encode()
	print("\noriginal string: ", message)
	#message= bytes(message,"utf-8")

	publickey = RSA.import_key(publicKeyStr)

	cipher = PKCS1_OAEP.new(publickey)

	encryptedMessage = cipher.encrypt(message)

	response = {'encryptedUID':list(encryptedMessage),'publicKey':publicKeyStr,'privateKey':privateKeyStr}

	return jsonify(response), 200


userRandomByte=b''
app.run(host='127.0.0.1', port=5000)

