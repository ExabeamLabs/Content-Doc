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
    """"@timestamp":"({time}\d\d\d\d\-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"deviceIP":"({host}[A-Fa-f:\d.]+)""",
    """"srcIP":"({src_ip}[A-Fa-f:\d.]+)""",
    """"dstIP":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"alertURL":"({malware_url}[^"]+)""",
    """"malwareName":\s*"({alert_name}[^"]+)""",
    """"malwareSType":"({alert_type}[^"]+)""",
    """"srcHostname":"({src_host}[\w\-.]+)""",
    """"severity":"({alert_severity}[^"]+)""",
    """"deviceSensor":"({sensor}[^"]+)""",
    """"protocol":"({protocol}[^"]+)""",
    """"srcPort":"({src_port}\d+)""",
  ]
}
```