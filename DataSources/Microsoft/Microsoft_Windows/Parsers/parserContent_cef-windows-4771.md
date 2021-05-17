#### Parser Content
```Java
{
Name = cef-windows-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4771"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4771"""", """Kerberos pre-authentication failed""" ]
  Fields = [
    """"systemTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"computer":"({host}[\w\-.]{1,2000})""",
    """"message":"({event_name}[^"]{1,2000}?)\s{0,100}"""",
    """"eventID":"({event_code}\d{1,100})""",
    """"eventRecordID":"({record_id}\d{1,100})""",
    """"severityValue":"({outcome}[^"]{1,2000}?)\s{0,100}"""",
    """"targetSid":"({user_sid}[^"\s]{1,2000}?)\s{0,100}"""",
    """"targetUserName":"({user}[^"\s]{1,2000}?)\s{0,100}"""",
    """"serviceName":"({src_host}[\w\-.]{1,2000})\/({domain}[^\\\/\s"]{1,2000}?)\s{0,100}"""",
    """"status":"({result_code}[^"]{1,2000}?)\s{0,100}""""
  ]
}
```