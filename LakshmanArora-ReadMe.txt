Unzip "LakshmanArora-cs6903s17project2"
Copy the directory "LakshmanArora-cs6903s17project2" to Desktop
Move to directory 'Project'

To Generate RSA Keys - In terminal run the command
	python pki.py

Move any text file to the client directory that you would like to upload and test. 
Test File named 'xyz' is available and stored in the directory named 'Client'
Run the 'Client' program using the command - 
	python client.py
	
	Choose option of Upload File. Enter value '1'

	Enter file name to upload. Enter 'xyz'
	
This will file will be uploaded and can be verified in the 'Cloud' directory. 

Run the 'Client' program using the command - 
	python client.py
	
	Choose option of Download File. Enter value '2'
	
	Enter file name to download. Enter 'xyz'
	
This will file will be downloaded and can be verified in the 'Client' directory.
The file will be named 'xyz_download'. 