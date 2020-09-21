#### Parser Content
```Java
{
Name = cef-microsoft-graph-activity
 Vendor = Microsoft
 Product = Microsoft Office 365 
 DataType = "failed-app-login"
 Lms = Direct
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
 Conditions = [ """appDisplayName":""", """"src-endpoint":"Graph Sign-In logs"""","""failureReason":""", """event-name":"login-failed""" ]
 Fields =[
   """"+time"+:"+({time}[^"]+)""",
   """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+({host}[^\s]+)\s+Skyformation""",
   """"+event-name"+:"+({event_name}[^"]+)""",
   """"+userDisplayName"+:"+({user_fullname}[^"]+)""",
   """"+userPrincipalName"+:"+({user_email}[^"]+)""",
   """"+userId"+:"+({user_id}[^"]+)""",
   """"+appDisplayName"+:"+({app}[^"]+)""",
   """"+ipAddress"+:"+({src_ip}[^"]+)""",
   """"+clientAppUsed"+:"+({object}[^"]+)""",
   """"+resourceDisplayName"+:"+({resource}[^"]+)""",
   """"+status"+.+?failureReason":"+({failure_reason}[^"]+)""",
   """"+additionalDetails":"+({additional_info}[^"]+)""",
   """"+deviceDetail".+?operatingSystem"+:"+({os}[^"]+)""",
   """"+location".+?city"+:"+({location_city}[^",]+)""",
   """"+location".+?state"+:"+({location_state}[^",]+)""",
   """"+location".+?countryOrRegion"+:"+({location_country}[^",]+)""",
   """"+application-action"+:"+({activity}[^"]+)""",
   """"+application-action".+?status"+.+?code":"+({outcome}[^"]+)""",
   """"+src-endpoint"+:"+({endpoint}[^"]+)""",
   """"+src-account-name"+:"+({account}[^"]+)""",
 ]
}
```