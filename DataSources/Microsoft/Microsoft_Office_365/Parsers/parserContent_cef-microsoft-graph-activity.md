#### Parser Content
```Java
{
Name = cef-microsoft-graph-activity
  DataType = "failed-app-login"
  Conditions = [ """appDisplayName":""", """"src-endpoint":"Graph Sign-In logs"""","""failureReason":""", """event-name":"login-failed""" ]
  Fields = ${MSParserTemplates.cef-o365-app-login.Fields} [
    """"{1,20}status"{1,20}.+?failureReason":"{1,20}({failure_reason}[^"]{1,2000})""",
  ]
}
cef-o365-app-login = {
   Vendor = Microsoft
   Product = Microsoft Office 365
   DataType = "app-login"
   Lms = Direct
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
   Fields =[
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """"{1,20}time"{1,20}:"{1,20}({time}[^"]{1,2000})""",
     """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)\s{1,100}[^\s]{1,2000}\s{1,100}Skyformation""",
     """"{1,20}event-name"{1,20}:"{1,20}({event_name}[^"]{1,2000})""",
     """"{1,20}userDisplayName"{1,20}:"{1,20}(({user_fullname}[^\s"]{1,2000}\s{1,100}[^"]{1,2000})|({user_id}[^"]{1,2000}))""",
     """"{1,20}userPrincipalName"{1,20}:"{1,20}(({user_email}[^@"]{1,2000}@[^"]{1,2000})|({user_id}[^"]{1,2000}))""",
     """"{1,20}userId"{1,20}:"{1,20}({user_id}[^"]{1,2000})""",
     """"{1,20}appDisplayName"{1,20}:"{1,20}({app}[^"]{1,2000})""",
     """"{1,20}ipAddress"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
     """"{1,20}clientAppUsed"{1,20}:"{1,20}({object}[^"]{1,2000})""",
     """"{1,20}resourceDisplayName"{1,20}:"{1,20}({resource}[^"]{1,2000})""",
     """"{1,20}additionalDetails":"{1,20}({additional_info}[^"]{1,2000})""",
     """"{1,20}deviceDetail".+?operatingSystem"{1,20}:"{1,20}({os}[^"]{1,2000})""",
     """"{1,20}location".+?city"{1,20}:"{1,20}({location_city}[^",]{1,2000})""",
     """"{1,20}location".+?state"{1,20}:"{1,20}({location_state}[^",]{1,2000})""",
     """"{1,20}location".+?countryOrRegion"{1,20}:"{1,20}({location_country}[^",]{1,2000})""",
     """"{1,20}application-action"{1,20}:"{1,20}({activity}[^"]{1,2000})""",
     """"{1,20}application-action".+?status"{1,20}.+?code":"{1,20}({outcome}[^"]{1,2000})""",
     """"{1,20}src-endpoint"{1,20}:"{1,20}({endpoint}[^"]{1,2000})""",
     """"{1,20}src-account-name"{1,20}:"{1,20}({account}[^"]{1,2000})""",
     """"{1,20}src-account-name"{1,20}:"{1,20}({account_name}[^"]{1,2000})""",
   ]

```