#### Parser Content
```Java
{
Name = cef-microsoft-graph-activity
  DataType = "failed-app-login"
  Conditions = [ """appDisplayName":""", """"src-endpoint":"Graph Sign-In logs"""","""failureReason":""", """event-name":"login-failed""" ]
  Fields = ${MSParserTemplates.cef-o365-app-login.Fields} [
    """"+status"+.+?failureReason":"+({failure_reason}[^"]+)""",
  ]
}
cef-o365-app-login = {
   Vendor = Microsoft
   Product = Microsoft Office 365
   DataType = "app-login"
   Lms = Direct
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
   Fields =[
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """"+time"+:"+({time}[^"]+)""",
     """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+[^\s]+\s+Skyformation""",
     """"+event-name"+:"+({event_name}[^"]+)""",
     """"+userDisplayName"+:"+(({user_fullname}[^\s"]+\s+[^"]+)|({user_id}[^"]+))""",
     """"+userPrincipalName"+:"+(({user_email}[^@"]+@[^"]+)|({user_id}[^"]+))""",
     """"+userId"+:"+({user_id}[^"]+)""",
     """"+appDisplayName"+:"+({app}[^"]+)""",
     """"+ipAddress"+:"+({src_ip}[^"]+)""",
     """"+clientAppUsed"+:"+({object}[^"]+)""",
     """"+resourceDisplayName"+:"+({resource}[^"]+)""",
     """"+additionalDetails":"+({additional_info}[^"]+)""",
     """"+deviceDetail".+?operatingSystem"+:"+({os}[^"]+)""",
     """"+location".+?city"+:"+({location_city}[^",]+)""",
     """"+location".+?state"+:"+({location_state}[^",]+)""",
     """"+location".+?countryOrRegion"+:"+({location_country}[^",]+)""",
     """"+application-action"+:"+({activity}[^"]+)""",
     """"+application-action".+?status"+.+?code":"+({outcome}[^"]+)""",
     """"+src-endpoint"+:"+({endpoint}[^"]+)""",
     """"+src-account-name"+:"+({account}[^"]+)""",
     """"+src-account-name"+:"+({account_name}[^"]+)""",
   ]

```