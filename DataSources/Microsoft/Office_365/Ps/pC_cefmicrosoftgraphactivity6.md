#### Parser Content
```Java
{
Name = cef-microsoft-graph-activity-6
  Conditions = [ """"event-name":""", """"src-endpoint":"mcas-activities"""", """"activityResult":""", """event-name":"login-success""" ]
  Fields = ${MSParserTemplates.cef-o365-app-login-1.Fields} [
    """"prettyOperationName"{1,20}:"{1,20}({protocol}[^",]{1,2000})""",
    """"userName"{1,20}:"{1,20}({user_email}[^@",\s]{1,2000}@[^",]{1,2000})""",
    """"userAgent"{1,20}:"{1,20}({user_agent}[^",]{1,2000})"""
  ]

cef-o365-app-login-1 = {
   Vendor = Microsoft
   Product = Office 365
   DataType = "app-login"
   Lms = Direct
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
   Fields =[
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)\s{1,100}[^\s]{1,2000}\s{1,100}""",
     """"event-name":"({activity}[^"]{1,2000})""",
     """app-user-displayname":"({user_fullname}[^\s"]{1,2000}\s{1,100}[^"]{1,2000})""",
     """user-email":"({user_email}[^@"]{1,2000}@[^"]{1,2000})""",
     """app-user-id":"({user_id}[\w-]{1,2000})""",
     """appName":"({app}[^"]{1,2000})""",
     """ApplicationName":"({app}[^"]{1,2000})""",
     """src-ip":"({src_ip}[\da-fA-F\.:]{1,2000})""",
     """device":[^}]{1,2000}?"os":[^}]{1,2000}?"name":"({os}[^"]{1,2000})""",
     """browser":"((?i)(unknown)|({browser}[^"]{1,2000}))""",
     """"location"[^}]{1,2000}?city"{1,20}:"{1,20}({location_city}[^",]{1,2000})""",
     """"location"[^}]{1,2000}?countryCode":"({location_country}[^",]{1,2000})""",
     """"location"[^}]{1,2000}?region":"({region}[^",]{1,2000})""",
     """activityResult":[^}]{1,2000}?"isSuccess":({outcome}(?i)(true|false))""",
     """"application-action":"({event_name}[^"]{1,2000})""",
     """"src-endpoint":"({endpoint}[^"]{1,2000})""",
     """"src-account-name":"({account}[^"]{1,2000})""",
     """"src-account-name":"({account_name}[^"]{1,2000})""",
   
}
```