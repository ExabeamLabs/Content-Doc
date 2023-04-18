#### Parser Content
```Java
{
Name = ping-authentication-failed-1
  DataType = "authentication-failed"
  Conditions = [ """"source":"PINGID"""",""""type":"user"""",""""status":"FAILURE,authFail"""",""""message":""",""""resources":""",""""result":{""" ]
  Fields = ${PingParserTemplates.ping-authentication_events.Fields}[
    """"status":"({outcome}FAILURE)""",
    """"message":"({failure_reason}[^}]{1,2000}?)"\s{0,100}\}""",
  ]

ping-authentication_events = {
    Vendor = Ping Identity
    Product = Ping Identity
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"recorded":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """"name":\s{0,100}"(({user_email}[^"@\s]{1,2000}@[^"]{1,2000})|({user}[^"]{1,2000}))"""",
    
}
```