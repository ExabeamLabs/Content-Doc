#### Parser Content
```Java
{
Name = fireeyecm-nx-alert
  Vendor = FireEye
  Product = FireEye Endpoint Security (CM)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"FireEyeCM"""", """"NX"""", """"malwareName":"""", """"malwareSType":"""" ]
  Fields = [
    """"@timestamp":"({time}\d\d\d\d\-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"deviceIP":"({host}[A-Fa-f:\d.]{1,2000})""",
    """"srcIP":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"dstIP":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"alertURL":"({malware_url}[^"]{1,2000})""",
    """"malwareName":\s{0,100}"({alert_name}[^"]{1,2000})""",
    """"malwareSType":"({alert_type}[^"]{1,2000})""",
    """"srcHostname":"({src_host}[\w\-.]{1,2000})""",
    """"severity":"({alert_severity}[^"]{1,2000})""",
    """"deviceSensor":"({sensor}[^"]{1,2000})""",
    """"protocol":"({protocol}[^"]{1,2000})""",
    """"srcPort":"({src_port}\d{1,100})""",
  ]
}
```