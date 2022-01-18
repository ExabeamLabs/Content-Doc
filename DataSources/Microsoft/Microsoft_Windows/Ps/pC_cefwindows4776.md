#### Parser Content
```Java
{
Name = cef-windows-4776
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4776"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4776"""", """attempted to validate the credentials for an account""" ]
  Fields = [
    """"systemTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"computer":"({host}[\w\-.]{1,2000})""",
    """"message":"({event_name}[^"]{1,2000}?)\s{0,100}"""",
    """"eventID":"({event_code}\d{1,100})""",
    """"eventRecordID":"({record_id}\d{1,100})""",
    """"severityValue":"({outcome}[^"]{1,2000}?)\s{0,100}"""",
    """"targetUserName":"({user}[^"\s@]{1,2000}?)\s{0,100}"""",
    """"targetUserName":"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000}?)\s{0,100}"""",
    """"workstation":"({dest_host}[^"\s]{1,2000}?)\s{0,100}"""",
    """"status":"({result_code}[^"]{1,2000}?)\s{0,100}"""",
  ]


}
```