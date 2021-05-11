#### Parser Content
```Java
{
Name = cef-microsoft-graph-activity-3
  DataType = "failed-app-login"
  Conditions = [ """"event-name":""", """"src-endpoint":"mcas-activities"""", """"activityResult":""", """event-name":"login-failed""" ]
  Fields = ${MSParserTemplates.cef-o365-app-login-1.Fields} [
    """activityResult":[^}]+?message":"({failure_reason}[^"]+)""",  
  ]
}
cef-o365-app-login-1 = {
   Vendor = Microsoft
   Product = Microsoft Office 365
   DataType = "app-login"
   Lms = Direct
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
   Fields =[
     """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
     """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)\s{1,100}[^\s]+\s{1,100}Skyformation""",
     """"event-name":"({activity}[^"]+)""",
     """app-user-displayname":"({user_fullname}[^\s"]+\s{1,100}[^"]+)""",
     """user-email":"({user_email}[^@"]+@[^"]+)""",
     """app-user-id":"({user_id}[\w-]+)""",
     """appName":"({app}[^"]+)""",
     """ApplicationName":"({app}[^"]+)""",
     """src-ip":"({src_ip}[\da-fA-F\.:]+)""",
     """device":[^}]+?"os":[^}]+?"name":"({os}[^"]+)""",
     """browser":"((?i)(unknown)|({browser}[^"]+))""",
     """"location"[^}]+?city"{1,20}:"{1,20}({location_city}[^",]+)""",
     """"location"[^}]+?countryCode":"({location_country}[^",]+)""",
     """"location"[^}]+?region":"({region}[^",]+)""",
     """activityResult":[^}]+?"isSuccess":({outcome}(?i)(true|false))""",
     """"application-action":"({event_name}[^"]+)""",
     """"src-endpoint":"({endpoint}[^"]+)""",
     """"src-account-name":"({account}[^"]+)""",
     """"src-account-name":"({account_name}[^"]+)""",
   ]

```