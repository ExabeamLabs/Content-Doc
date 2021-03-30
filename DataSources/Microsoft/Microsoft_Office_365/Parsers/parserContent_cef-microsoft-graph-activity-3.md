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
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+[^\s]+\s+Skyformation""",
     """"event-name":"({activity}[^"]+)""",
     """app-user-displayname":"({user_fullname}[^\s"]+\s+[^"]+)""",
     """user-email":"({user_email}[^@"]+@[^"]+)""",
     """app-user-id":"({user_id}[\w-]+)""",
     """appName":"({app}[^"]+)""",
     """ApplicationName":"({app}[^"]+)""",
     """src-ip":"({src_ip}[\da-fA-F\.:]+)""",
     """device":[^}]+?"os":[^}]+?"name":"({os}[^"]+)""",
     """browser":"((?i)(unknown)|({browser}[^"]+))""",
     """"location"[^}]+?city"+:"+({location_city}[^",]+)""",
     """"location"[^}]+?countryCode":"({location_country}[^",]+)""",
     """"location"[^}]+?region":"({region}[^",]+)""",
     """activityResult":[^}]+?"isSuccess":({outcome}(?i)(true|false))""",
     """"application-action":"({event_name}[^"]+)""",
     """"src-endpoint":"({endpoint}[^"]+)""",
     """"src-account-name":"({account}[^"]+)""",
     """"src-account-name":"({account_name}[^"]+)""",
   ]

```