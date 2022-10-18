<%@ page import="java.util.*, java.lang.*"  language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>DSS Cryptography</title>
</head>

<%
boolean process = false;

String user_ID = "";
int domain = 0;
String resultSetRSAStatic="";
String resultSetRSAStatic_noVerify="";
String resultVerifyRSAStatic="";
String resultChangeRSAStatic="";
String resultChangeRSAStatic_noVerify="";
String resultTranslateRSAStatic="";
String resultVerify2Factor="";   
%>


<body>

	<form name="registration" id="registration_form_id" action=""
		method="post" onsubmit="return doSubmit(this)">
		<table border=0 width="50%">
			<tr>
				<td colspan="3"><label>API List : </label></td>
			</tr>
			<tr>
				<td colspan="3">&nbsp;</td>
			</tr>
			<tr>
				<td>&nbsp;</td>
				<td><b>API Name</b></td>
				<td><b>Result</b></td>
			</tr>
			<tr>
				<td><input type="checkbox" name="api[]" value="setRSAStatic">
				</td>
				<td>setRSAStatic</td>
				<td><%= resultSetRSAStatic%></td>
			</tr>
			<tr>
				<td><input type="checkbox" name="api[]"
					value="setRSAStatic_noVerify"></td>
				<td>setRSAStatic_noVerify</td>
				<td><%= resultSetRSAStatic_noVerify%></td>
			</tr>
			<tr>
				<td><input type="checkbox" name="api[]" value="verifyRSAStatic">
				</td>
				<td>verifyRSAStatic</td>
				<td><%= resultVerifyRSAStatic%></td>
				<td></td>
			</tr>
			
			
			<tr>
				<td><input type="checkbox" name="api[]"
					value="verify2Factor"></td>
				<td>verify2Factor</td>
				<td><%= resultVerify2Factor %></td>
				<td></td>
			</tr>
			
			<tr>
				<td><input type="checkbox" name="api[]"
					value="changeRSAStatic"></td>
				<td>changeRSAStatic</td>
				<td><%= resultChangeRSAStatic%></td>
				<td></td>
			</tr>
			
			<tr>
				<td><input type="checkbox" name="api[]"
					value="changeRSAStatic_noVerify"></td>
				<td>changeRSAStatic_noVerify</td>
				<td><%= resultChangeRSAStatic_noVerify %></td>
				<td></td>
			</tr>


			<tr>
				<td><input type="checkbox" name="api[]"
					value="translateRSAStatic"></td>
				<td>translateRSAStatic</td>
				<td><%= resultTranslateRSAStatic %></td>
				<td></td>
			</tr>

			<tr>
				<td colspan="3">&nbsp;</td>
			</tr>

			<tr>
				<td colspan="3"><label for="domainID">Domain ID: </label><input type="text" name="domainID" placeholder="Domain ID" style="margin-left: 24px"/></td>
			</tr>

			<tr>
				<td colspan="3"><label for="userID">UserName: </label><input type="text" name="userID" placeholder="UserName" style="margin-left: 28px"/></td>
			</tr>

			<tr>
				<td colspan="3"><label for="password">Password: </label><input type="text" name="password" placeholder="Current Password" style="margin-left: 35px"/></td>
			</tr>

			<tr>
				<td colspan="3"><label for="OTIP">OTIP:    </label><input type="text" name="OTIP" placeholder="OTIP" style="margin-left: 60px"/></td>
			</tr>

			<tr>
				<td colspan="3"><label for="newPassword">New Password: </label><input type="text" name="newPassword" placeholder="New Password" /></td>
			</tr>

			<tr>
				<td colspan="3">&nbsp;</td>
			</tr>

			<tr>
				<td colspan="3">Select Random Length. Default: 16</td>
			</tr>

			<tr>
				<td><input type="radio" id="randomLength16" name="randomLength" value="16" checked></td>
				<td>Ramdom 16Byte</td>
			</tr>
			
			<tr>
				<td><input type="radio" id="randomLength32" name="randomLength" value="32"></td>
				<td>Ramdom 32Byte</td>
			</tr>

			<tr>
				<td colspan="3">&nbsp;</td>
			</tr>

			<tr>
				<td colspan="3">Select Hash Algorithm</td>
			</tr>

			<tr>
				<td><input type="radio" id="HashAlgoMD5" name="HashAlgo" value="MD5" checked></td>
				<td>MD5</td>
			</tr>
			
			<tr>
				<td><input type="radio" id="HashAlgoSHAFold" name="HashAlgo" value="SHA256FOLD"></td>
				<td>SHA256FOLD</td>
			</tr>

			<tr>
				<td><input type="radio" id="HashAlgoSHA" name="HashAlgo" value="SHA256"></td>
				<td>SHA256</td>
			</tr>
			
			<tr>
				<td colspan="3">&nbsp;</td>
			</tr>
			<tr>
				<td colspan="3"><button type="submit">Submit</button></td>
			</tr>
		</table>
		<input type="hidden" name="process" id="process"> 
		<input type="hidden" name="rsaBlockSetRSAStatic" id="rsaBlockSetRSAStatic"> 
		<input type="hidden" name="rsaBlockSetRSAStatic_noVerify"	id="rsaBlockSetRSAStatic_noVerify">
		<input type="hidden" name="rsaBlockVerifyRSAStatic" id="rsaBlockVerifyRSAStatic">
		<input type="hidden" name="rsaBlockVerify2Factor" id="rsaBlockVerify2Factor">
		<input type="hidden" name="rsaBlockChangeRSAStatic" id="rsaBlockChangeRSAStatic">
		<input type="hidden" name="rsaBlockChangeRSAStatic_noVerify" id="rsaBlockChangeRSAStatic_noVerify">
		<input type="hidden" name="rsaBlockTranslateRSAStatic" id="rsaBlockTranslateRSAStatic">
		<input type="hidden" name="random1" id="random1">
		<input type="hidden" name="random2" id="random2">
		
	</form>
</body>
</html>