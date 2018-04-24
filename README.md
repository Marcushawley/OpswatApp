ReadMe

This application is written in java ( version 1.8)

The application accepts parameter API Key and complete FILE_NAME( with path) through command line

javac -cp "./lib/gson-2.8.2.jar;" ThreatScanner.java

To Run the application use following command:

java  -cp "./lib/gson-2.8.2.jar;" ThreatScanner <API_Key> <FILE_NAME>


Upon executing ThreatScanner class, For each responses, Api key is sent in header

1) Hash for the given File is computed using HashFile class

2) Computed Hash is checked against https://api.metadefender.com/v2/hash/:hash to get the cache results and are printed

3) If not found in cache, file upload request is sent and the data id is recieved on successful request https://api.metadefender.com/v2/file/

4) The data_id and rest_ip is used to then get the scan results https://rest_ip/file/:data_id
5) The scan request is pulled repeatedly until progress_percentage is 100.
6) Finally scan results are printed