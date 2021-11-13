#### Parser Content
```Java
{
Name = json-eyeinspect-failed-logon
  Vendor = Forescout
  Product = EyeInspect
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat =  "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"action":"Failed login"""", """"resource":"Operating system Command Center"""", """"clientIP":""", """"user":"""", """"otherInfo":"""" ]
  Fields = [
    """exabeam_host=(({host_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({host}[\w.\-]{1,2000}))""", 
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """"user":"({user}[^",]{1,2000})"""",
    """"clientIP":"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """({outcome}Failed)""",
    """"otherInfo":"({failure_reason}[^",]{1,2000})"""",
    """"action":"({event_name}[^",]{1,2000})""""
  ]


}
```