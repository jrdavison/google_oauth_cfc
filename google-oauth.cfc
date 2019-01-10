<!---
Author: jrdavison (jmsrdvsn@gmail.com)
--->
<cfcomponent>

	<cffunction name="getAuthToken" access="public" returntype="struct">
		<cfargument name="scope" type="string" required="yes">

		<!--- get parameters for http request from file --->
		<cffile file="#<!---PATH TO KEY FILE--->#" action="read" variable="authFile">
		<cfset authParams = deserializeJSON(authFile)>
		
		<!--- get timestamp UTC / adjust for daylight savings --->
		<cfset timeStamp = DateDiff("s", "January 1 1970 00:00", DateConvert('local2UTC', Now()).toString())>
		<cfif GetTimeZoneInfo().isDSTon>
			<cfset timeStamp = timeStamp + 3600>
		</cfif>
		
		<!--- header --->
		<cfset header 		    = structNew()>
		<cfset header["alg"] 	= "RS256">
		<cfset header["typ"] 	= "JWT">
		<cfset JWT 		    	= base64urlEncode(serializeJSON(header))>
		
		<!--- claim --->
		<cfset claim 		    = structNew()>
		<cfset claim["iss"] 	= authParams.client_email>
		<cfset claim["scope"] 	= ARGUMENTS.scope>
		<cfset claim["aud"] 	= "https://www.googleapis.com/oauth2/v4/token">
		<cfset claim["exp"] 	= Timestamp + 2400>
		<cfset claim["iat"] 	= Timestamp>
		<cfset JWT 			    = "#JWT#.#base64urlEncode(serializeJSON(claim))#">
		
		<!--- strip delimiters from key --->
		<cfset key = authParams.private_key>
		<cfset key = reReplace(key, "-----BEGIN PRIVATE KEY-----", "", "all")>
		<cfset key = reReplace(Key, "-----END PRIVATE KEY-----", "", "all")>
		<cfset key = reReplace(key, "\n", "", "all")>
		
		<!--- sign JWT --->
		<cfinvoke method="encryptString" returnVariable="signature">
			<cfinvokeargument name="inputString" value="#JWT#">
			<cfinvokeargument name="key" value="#key#">
		</cfinvoke>
		
		<!--- JWT format: header.claim.signature (all base64 encoded and appended together by '.')--->
		<cfset JWT = "#JWT#.#signature#">
		
		<cftry>
			<cfhttp method="POST" url="https://www.googleapis.com/oauth2/v4/token" timeout="30" result="authToken">
				<cfhttpparam type="header" name="content-type" value="application/x-www-form-urlencoded; charset=utf-8">
				<cfhttpparam type="formField" name="grant_type" value="urn:ietf:params:oauth:grant-type:jwt-bearer">
				<cfhttpparam type="formField" name="assertion" value="#JWT#">
			</cfhttp>

			<cfcatch>
				
				<!---

					Handle error catching for failed http requests here

				--->

			</cfcatch>
		</cftry>
	
		<cfreturn authToken>
	</cffunction>
	
	<cffunction name="base64urlEncode" access="private" returntype="string">
		<cfargument name="inputString" type="string" required="yes">
		
		<cfset bytes = charsetDecode(ARGUMENTS.inputString, "utf-8")>
		
		<cfset encodedValue = binaryEncode(bytes, "base64")>
		
		<cfset encodedValue = replace(encodedValue, "+", "-", "all")>
		<cfset encodedValue = replace(encodedValue, "/", "_", "all")>
        <cfset encodedValue = replace(encodedValue, "=", "", "all")>
		
		<cfreturn encodedValue>
	</cffunction>
	
	<cffunction name="encryptString" access="private" returntype="string">
		<cfargument name="inputString" type="string" required="yes">
		<cfargument name="key" type="string" required="yes">
		
		<!--- Init java Objects --->
		<cfset keyFactory 		= createObject("java", "java.security.KeyFactory")>
		<cfset encodedKeySpec	= createObject("java", "java.security.spec.PKCS8EncodedKeySpec")>
		<cfset signature 		= createObject("java", "java.security.Signature")>
		
		<!--- 
			Convert key to binary value
			Generate private key from binary value using RSA algorithm
		--->
		<cfset privateKeySpec	= encodedKeySpec.init(binaryDecode(ARGUMENTS.key, "base64"))>
		<cfset privateKey 		= keyFactory.getInstance(javaCast("string", "RSA")) 
							  				.generatePrivate(privateKeySpec)>
		
		<!---
			Choose encryption algorithm
			Add string to be encrypted and key to encrypt value to the signer object
		--->
		<cfset signer = signature.getInstance(javaCast("string", "SHA256withRSA"))>
		<cfset signer.initSign(privateKey)>
		<cfset signer.update(charsetDecode(inputString, "utf-8"))>
		
		<!--- 
			Encrypt the string
			Revert the encrypted binary value back to a base64 encoded string
		--->
		<cfset signedBytes 	= signer.sign()>
		<cfset signature 	= binaryEncode(signedBytes, "base64")>
		
		<cfreturn signature>
	</cffunction>

</cfcomponent>
