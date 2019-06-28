<!---
Author: jrdavison (jmsrdvsn@gmail.com)
Date: 08/18/17
Updated: 06/28/19

References:
    https://developers.google.com/identity/protocols/OAuth2ServiceAccount
    https://tools.ietf.org/html/rfc7515
--->

<cfcomponent>

    <cffunction name="getAuthToken" access="private" returntype="struct">
        <cfargument name="scope" type="string" required="yes">

        <cfset var result = structNew()>
        <cfset result.success = true>

        <cftry>
            <!--- get parameters for http request from key.json file --->
            <cffile file="<!--- PATH TO KEY FILE --->" action="read" variable="authFile">
            <cfset var authParams = deserializeJSON(authFile)>

            <!--- get timestamp --->
            <cfset var timestamp = DateDiff("s", "January 1 1970 00:00", DateConvert('local2UTC', Now()).toString())>
            <!--- check for daylight savings --->
            <cfif GetTimeZoneInfo().isDSTon>
                <cfset timestamp = timestamp + 3600>
            </cfif>

            <!---
                create hash table with entries connected by a linked list
                    - coldfusion automatically sorts struct keys alphabetically. This prevents that

                https://docs.oracle.com/javase/8/docs/api/java/util/LinkedHashMap.html
            --->
            <cfset var orderedStruct  = createObject("java", "java.util.LinkedHashMap")>

            <cfset var header = orderedStruct.init()>
            <cfset header["alg"] = "RS256">
            <cfset header["typ"] = "JWT">

            <cfset var JWT = base64urlEncode(inputString=serializeJSON(header))>

            <cfset var claim = orderedStruct.init()>
            <cfset claim["iss"] = authParams.client_email>
            <cfset claim["scope"] = ARGUMENTS.scope>
            <cfset claim["aud"] = "https://www.googleapis.com/oauth2/v4/token">
            <cfset claim["exp"] = timestamp + 2400>
            <cfset claim["iat"] = timestamp>
            <cfset JWT = "#JWT#.#base64urlEncode(intputString=serializeJSON(claim))#">

            <!--- Strip delimiters from key --->
            <cfset var key = authParams.private_key>
            <cfset key = reReplace(key, "-----BEGIN PRIVATE KEY-----", "", "all")>
            <cfset key = reReplace(key, "-----END PRIVATE KEY-----", "", "all")>
            <cfset key = reReplace(key, "\n", "", "all")>

            <cfset var signature = encryptString(inputString=JWT, key=key)>

            <cfset JWT = "#JWT#.#signature#">

            <cfhttp method="POST" url="https://www.googleapis.com/oauth2/v4/token" timeout="30" result="response">
                <cfhttpparam type="header" name="content-type" value="application/x-www-form-urlencoded; charset=utf-8">
                <cfhttpparam type="formField" name="grant_type" value="urn:ietf:params:oauth:grant-type:jwt-bearer">
                <cfhttpparam type="formField" name="assertion" value="#JWT#">
            </cfhttp>

            <cfif response.statusCode NEQ "200 OK">
                <cfthrow message="[Google OAuth2 API]: #response.errorDetail# (#response.statusCode#)">
            </cfif>
            <cfset result.authToken = deserializeJSON(response.fileContent).access_token>

            <cfcatch>
                <cfset result.success = false>
                <cfset result.msg = cfcatch.message>
            </cfcatch>
        </cftry>

        <cfreturn result>
    </cffunction>

    <cffunction name="base64urlEncode" access="private" returntype="string">
        <cfargument name="inputString" type="string" required="yes">

        <!--- binary representation of  utf-8 string --->
        <cfset var bytes = charsetDecode(ARGUMENTS.inputString, "UTF-8")>

        <!--- encode binary value using base64 characters --->
        <cfset var encodedValue = binaryEncode(bytes, "base64")>

        <!---
            replace characters not allowed in base64url format.
            the chars [+, /, =] have significance in URLs.
        --->
        <cfset encodedValue = replace(encodedValue, "+", "-", "all")>
        <cfset encodedValue = replace(encodedValue, "/", "_", "all")>
        <cfset encodedValue = replace(encodedValue, "=", "", "all")>

        <cfreturn encodedValue>
    </cffunction>

    <cffunction name="encryptString" access="private" returntype="string">
        <cfargument name="inputString" type="string" required="yes">
        <cfargument name="key" type="string" required="yes">

        <!--- init java objects --->
        <cfset var keyFactory = createObject("java", "java.security.KeyFactory")>
        <cfset var encodedKeySpec = createObject("java", "java.security.spec.PKCS8EncodedKeySpec")>
        <cfset var signature = createObject("java", "java.security.Signature")>

        <!--- convert key to binary value / generate private key from binary value --->
        <cfset var privateKeySpec = encodedKeySpec.init(binaryDecode(ARGUMENTS.key, "base64"))>
        <cfset var privateKey = keyFactory.getInstance(javaCast("string", "RSA"))
                                          .generatePrivate(privateKeySpec)>

        <!--- choose encryption algorithm / add string to be encrypted --->
        <cfset var signer = signature.getInstance(javaCast("string", "SHA256withRSA"))>
        <cfset signer.initSign(privateKey)>
        <cfset signer.update(charsetDecode(ARGUMENTS.inputString, "utf-8"))>

        <!--- encrypt the string / revert the encrypted binary value back to a string --->
        <cfset var signedBytes = signer.sign()>
        <cfset var signature = binaryEncode(signedBytes, "base64")>

        <cfreturn signature>
    </cffunction>

</cfcomponent>

