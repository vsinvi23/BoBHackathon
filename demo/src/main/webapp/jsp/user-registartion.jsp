<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%
String contextPath = request.getContextPath();
%>
   
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
  <title>Welcome: User Registration</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!--css-->
  <link rel="stylesheet" href="<%= contextPath%>/jsp/BootStrap/css/bootstrap.css">
  <!--BootStrap js and Jquery-->
  <script src="<%= contextPath%>/jsp/BootStrap/js/jquery.min.js"></script>
  <script src="<%= contextPath%>/jsp/BootStrap/js/bootstrap.js"></script>
  
  <!-- JavaScript code -->
  <script type="text/javascript">
  
  jQuery(document).ready(function(){
        // This section check, file is csv or not.
	   $("#registrationButton").click(function(event)
		{
            var userID = document.getElementById("usernameTextbox").value;
            var deviceID = document.getElementById("deviceIDBox").value;
            var contactNumber = document.getElementById("phoneNumberBox").value;
            var email = document.getElementById("emailTextbox").value;

		    var validphotoFileExtension = "jpeg";
			var fileUpload = document.getElementById("photoUploader");
			var uploadFileName = fileUpload.value;
			
			var startIndex = uploadFileName.indexOf(".")+1;
			var endIndex = uploadFileName.length;
			
			var uploadFileExtension = uploadFileName.substring(startIndex,endIndex);
			if(validphotoFileExtension != uploadFileExtension)
			{
				alert("Please select jpeg format photo.");
				event.preventDefault();
			}

            var validVoiceFileExtension = "mp3";
			var voiceFileUpload = document.getElementById("voiceUploader");
			var voiceUploadFileName = voiceFileUpload.value;
			
			var startIndexVoiceUpload = voiceUploadFileName.indexOf(".")+1;
			var endIndexVoiceUpload = voiceUploadFileName.length;
			
			var voiceUploadFileExtension = voiceUploadFileName.substring(startIndexVoiceUpload, endIndexVoiceUpload);
			if(validVoiceFileExtension != voiceUploadFileExtension)
			{
				alert("Please select mp3 format file.");
				event.preventDefault();
			}

            jQuery.ajax({
			        url: "<%=request.getContextPath()%>/user-registation",	
					type : "POST",
                    data : {

                    },
					success : function(result) {
						if (result != "User Registration reuqest has been prossed.")
						{
							
						}
					}
				})
		});
    });

  function doUserRegistration()
  {
	  	var UserIdValue = document.getElementById("usernameTextbox").value;
		var PinValue    = document.getElementById("passwordTextbox").value;
		var OtipValue   = document.getElementById("otipTextBox").value;
		var passwordHash= "MD5";

		// Check textFields
		if ( UserIdValue.length == 0)
		{
			alert('Enter UserName');
			event.preventDefault();
		}
		if ( PinValue.length == 0 )
		{
			alert( 'Enter Password');
			event.preventDefault();
		}
		if ( OtipValue.length == 0)
		{
			OtipValue = PinValue;
		}
		return;
	}
  </script>
</head>
<body style="background-color: #acceeb;">
  
<div class="container">
    <form action="login?action=authenticateUser" method="post">
        <div class="row" style="margin: 10px 0px 20 px 0px;">
        		<div class="col-sm-12" style="text-align: center;">
                	<h1>User Registration</h1>
                </div>
                <div class="col-sm-4">
				<label class="control-label"  for="usernameTextbox">UserID</label>
                <input type="text" id="usernameTextbox" name="usernameTextbox" placeholder="Enter UserID" style="width:-webkit-fill-available" />
                </div>
                <div class="col-sm-4">
					<label class="control-label"  for="deviceIDBox">Device ID</label>
                    <input type="text" id="deviceIDBox" name="deviceIDBox" placeholder="Enter DeviceID" style="width:-webkit-fill-available"/>
                </div>
                <div class="col-sm-4">
					<label class="control-label"  for="phoneNumberBox">Contact Number</label>
                    <input type="text" id="phoneNumberBox" name="phoneNumberBox" placeholder="Enter Phone Number" style="width:-webkit-fill-available" />
                </div>
				
				<div class="col-sm-12" style="text-align: center;">
                	<h1></h1>
                </div>
				
				<div class="col-sm-4">
				<label class="control-label"  for="usernameTextbox">Email ID</label>
                <input type="text" id="emailTextbox" name="emailTextbox" placeholder="Enter Email ID" style="width:-webkit-fill-available" />
                </div>
                <div class="col-sm-4">
					<label class="control-label"  for="deviceIDBox">Photo Uploader</label>
					<input type="file" id="photoUploader" name="photoUploader">
                </div>
                <div class="col-sm-4">
					<label class="control-label"  for="deviceIDBox">Voice Uploader</label>
					<input type="file" id="voiceUploader" name="voiceUploader">
                </div>
				
        </div>
        <br/>
        <div class="row">
                <div class="col-sm-12">
                    <input class="btn btn-primary" type="submit" id="registrationButton" value="Registration" style="width:-webkit-fill-available">
                </div>
        </div>
    </form>
</div>

</body>
</html>