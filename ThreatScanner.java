import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.util.Map.Entry;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

public class ThreatScanner {
	private enum Status {
		SUCCESS, RETRY, FAILURE
	};

	static Status status;
	private static String APIKEY;
	private static final String BASE_URL = "https://api.metadefender.com/v2/";
	private static int WAIT_TIME = 2000;
	
	static class StatusWithData {
		Status returnStatus;
		JsonObject jObj;
	}

	/*
	 * 1. Calculate the hash of the given samplefile.txt 2. Perform a hash lookup
	 * against metadefender.opswat.com and see if their are previously cached
	 * results for the file 3. If results found then skip to 6 4. If results not
	 * found then upload the file, receive a data_id 5. Repeatedly pull on the
	 * data_id to retrieve results 6. Display results in format below
	 */

	public static String getApiKey() {
		return APIKEY;
	}

	public static void setApiKey(String inp) {
		APIKEY = inp;
	}

	public static JsonObject lookUp(String fileName) {
		JsonObject jObj = null;
		String hash = HashFile.getHashFile(fileName);
		//System.out.println(hash);
		try {
			URL url = new URL(BASE_URL + "hash/" + hash);
			ThreatScanner.StatusWithData respData;
			
			int retryCount = 0;

			do {
				 respData = getRequest(url);
				 //System.out.println("In LookUp: retryCount = " + retryCount + " status code = " + respData.returnStatus);
				 
				 if (respData.returnStatus == Status.RETRY) {
				 	Thread.sleep(WAIT_TIME);
				 } else if (retryCount++ >= 5) {
				 	break;
				 }
			} while(respData.returnStatus == Status.RETRY);
			
			//System.out.println("In LookUp: retryCount = " + retryCount + " status code = " + respData.returnStatus);
			
			jObj = respData.jObj;
			//System.out.println("In LookUp:  json =" + jObj);
			
			if (respData.returnStatus == Status.SUCCESS) {
				if (jObj.has("scan_results")) {
					printResponse(jObj);
				} else {
					System.out.println("Hash Look Up Cannot Find the Entry for Hash :" + hash);
					System.out.println("Requesting for File Upload ");
					fileUploadRequest(fileName, BASE_URL + "file");
				}
			} else {
				System.out.println("Request Failed..");
				return null;
			}
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		} catch (InterruptedException e) {
			e.printStackTrace();
			return null;
		}

		return jObj;
	}

	public static void printErrorResponse(JsonObject Obj) {

		JsonObject errObj = Obj.getAsJsonObject("error");
		int errCode = errObj.get("code").getAsInt();
		JsonArray jarray = errObj.getAsJsonArray("messages");
		System.err.println("Error Code: " + errCode);
		for (JsonElement ele : jarray) {
			System.err.println(ele.getAsString());
		}
	}

	public static StatusWithData getRequest(URL url) {
		HttpURLConnection request = null;
		ThreatScanner.StatusWithData returnVal = new ThreatScanner.StatusWithData();
		returnVal.returnStatus = Status.FAILURE;
		returnVal.jObj = null;
		
		try {
			request = (HttpURLConnection) url.openConnection();
			request.setRequestMethod("GET");
			request.setRequestProperty("apikey", getApiKey());
			int responseCode = request.getResponseCode();
			System.out.println("Response Code: " + responseCode);

			if ((responseCode / 100) == 5) { // Server side error so retry after some delay
				returnVal.returnStatus = Status.RETRY;
			} else if ((responseCode / 100) == 2) {
				JsonParser jp = new JsonParser();
				JsonElement elem;
				elem = jp.parse(new InputStreamReader((InputStream) request.getContent()));

				returnVal.returnStatus = Status.SUCCESS;				
				returnVal.jObj = elem.getAsJsonObject();
				
				//System.out.println("Success json res = " + returnVal.jObj);
			} else { // Other error
				returnVal.returnStatus = Status.FAILURE;
				System.err.println("Error (httpcode != 200) in getRequest() ...");
			}
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return returnVal;
	}

	/*
	 * Print the scan results obtained from the server
	 */
	public static void printResponse(JsonObject jsonObj) {

		JsonObject scanResults = jsonObj.getAsJsonObject("scan_results");
		JsonObject scanDetails = scanResults.getAsJsonObject("scan_details");
		String status = scanResults.get("scan_all_result_a").getAsString();
		String fileInfo = jsonObj.getAsJsonObject("file_info").get("display_name").getAsString();

		System.out.println("filename: " + fileInfo);
		System.out.println("overall_status " + status);

		JsonObject jobj;
		Set<Entry<String, JsonElement>> entrySet = scanDetails.entrySet();
		for (Entry<String, JsonElement> engineSet : entrySet) {

			System.out.println("engine: " + engineSet.getKey());
			jobj = engineSet.getValue().getAsJsonObject();
			System.out.println("threat :" + jobj.get("threat_found").getAsString());
			System.out.println("scan_result :" + jobj.get("scan_result_i").getAsString());
			System.out.println("def_time : " + jobj.get("def_time").getAsString());
			System.out.println();
		}
	}
	
	/*
	 * Method to Post File to scan
	 */
	public static Status fileUploadRequest(String fileName, String strUrl) {
		URL url = null;
		int responseCode = 0;
		String dataId;
		String restIp;
		String boundaryString = Long.toHexString(System.currentTimeMillis());
		String lineSep = "\r\n"; // Line separator required by multipart/form-data.
		String charset = "UTF-8";
		File binaryFile = new File(fileName);
		try {
			url = new URL(strUrl);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			
			return Status.FAILURE;
		}
		HttpURLConnection conn = null;
		OutputStream outStream = null;
		PrintWriter requestBodyWriter = null;
		try {
			conn = (HttpURLConnection) url.openConnection();
			// Set parameters for the post request
			conn.setDoOutput(true);
			conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundaryString);
			conn.setRequestProperty("apikey", getApiKey());
			conn.connect();

			/*
			 * Get output stream of the request and write multipart request
			 */
			outStream = conn.getOutputStream();
			requestBodyWriter = new PrintWriter(new OutputStreamWriter(outStream, charset), true);
			requestBodyWriter.append("--" + boundaryString).append(lineSep);
			requestBodyWriter.append(
					"Content-Disposition: form-data; name=\"binaryFile\"; filename=\"" + binaryFile.getName() + "\"")
					.append(lineSep);
			requestBodyWriter.append("Content-Type: " + URLConnection.guessContentTypeFromName(binaryFile.getName()))
					.append(lineSep);
			requestBodyWriter.append("Content-Transfer-Encoding: binary").append(lineSep);
			requestBodyWriter.append(lineSep).flush();
			Files.copy(binaryFile.toPath(), outStream);
			outStream.flush();
			requestBodyWriter.append(lineSep).flush();
			requestBodyWriter.append("--" + boundaryString + "--").append(lineSep).flush();

			responseCode = conn.getResponseCode();
			System.out.println(responseCode);

			if (responseCode / 100 == 4) {
				System.out.println(responseCode + " Api Key not correct");
				return Status.FAILURE;
			} else if (responseCode / 100 == 5) {
				System.err.println(responseCode + " Internal server Error");
				return Status.RETRY;
			} else if (responseCode / 100 == 2) {
				// Convert to a JSON object to print data
				JsonParser jp = new JsonParser();
				JsonElement elem;
				try {
					elem = jp.parse(new InputStreamReader((InputStream) conn.getContent()));
					JsonObject jObj = elem.getAsJsonObject();
					//System.out.println("File upload request successful, Here is the response from the server: " + jObj);
					
					//Get the data_id from the response and send a file request
					if (jObj.has("data_id")) {
						dataId = jObj.get("data_id").getAsString();
						System.out.println("Data Id: " + dataId);
						
						//Send request to the url obtained in the response
						
						restIp = jObj.get("rest_ip").getAsString();
						URL reportURL = new URL("https://" + restIp + "/file/" + dataId);
						getReportAndPrint(reportURL);
					} else {
						System.err.println("Request for file Upload failed");
					}
					
					return Status.SUCCESS;
				} catch (JsonIOException e) {
					e.printStackTrace();
				} catch (JsonSyntaxException e) {
					e.printStackTrace();
				} catch (IOException e) {
					e.printStackTrace();
				}

			} else {
				return Status.FAILURE;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
			return Status.FAILURE;
		} finally {
			try {
				outStream.close();
				requestBodyWriter.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return Status.FAILURE;
	}
	
	/*
	 * Method to pull repeatedly with data_id and check for successful completion of the request 
	 */
	public static void getReportAndPrint(URL url) {
		int loopCount = 1;
		while (true) {
			System.out.println("getReportAndPrint() URL = " + url);
			ThreatScanner.StatusWithData respData = getRequest(url);

			JsonObject json = respData.jObj;
			System.out.println("Loop count = " + loopCount++);
			JsonObject scanResults = json.get("scan_results").getAsJsonObject();

			if (scanResults.has("progress_percentage")) {
				
				float progressPercentage = scanResults.get("progress_percentage").getAsFloat();
				System.out.println("Progress Percentage for the File Scan Result is: " + progressPercentage);
				//Check for the progress percentage of the current request
				if (progressPercentage < 100) {
					//if progress percentage is less than 100 repeatedly pull the scan results until the report is complete
					try {
						Thread.sleep(WAIT_TIME);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
					continue;

				} else if (progressPercentage == 100) {
					// successful response
					if (json.has("scan_results")) {
						System.out.println("Scan Request Successful ");
						printResponse(json);
					}else {
						System.err.println("Scan Request Successful, Bad Json Format");
					}
					break;

					// print the response
				} else {
					System.err.println("Percentage Greater than 100 Not Valid");
				}
			} else {
				// error
				if (json.has("error")) {
					printErrorResponse(json);
				}
				System.err.println("Scan Result is not found");
				break;
			}
		}
	}

	public static void main(String[] args) {
		if (args.length != 2) {
			System.out.println("Error: Program need two arguments: \n1) API key \n2) File to be scanned");
			
			return;
		}
		setApiKey(args[0]);
		lookUp(args[1]);
	}
}
