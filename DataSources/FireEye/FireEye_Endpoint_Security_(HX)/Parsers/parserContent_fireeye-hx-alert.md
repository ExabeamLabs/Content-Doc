#### Parser Content
```Java
{
Name = fireeye-hx-alert
  Vendor = FireEye
  Product = FireEye Endpoint Security (HX)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"FireEyeHX"""", """"HX"""", """"malwarePath":"""", """"malwareMD5":"""" ]
  Fields = [
    """"@timestamp":"({time}\d\d\d\d\-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"deviceIP":"({host}[A-Fa-f:\d.]{1,2000})""",
    """"deviceHostname":"({host}[\w\-.]{1,2000})""",
    """"srcIP":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"malwarePath":"({malware_url}[^"]{1,2000})""",
    """"userID":"(({domain}[^"\\\s]{1,2000})\\+)?({user}[^"\\\s]{1,2000})""",
    """"srcOS":"({os}[^"]{1,2000})""",
    """"process":\s{0,100}"({alert_name}[^"]{1,2000})""",
    """"log_type":"({alert_type}[^"]{1,2000})""",
    """"srcHostname":"({src_host}[\w\-.]{1,2000})""",
    """"malwareMD5":"({md5}[^"]{1,2000})""",
    """"deviceSensor":"({sensor}[^"]{1,2000})""",
  ]
}
```