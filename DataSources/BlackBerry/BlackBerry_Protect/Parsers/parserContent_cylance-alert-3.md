#### Parser Content
```Java
{
Name = cylance-alert-3
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"src-application-name":"CylanceProtect"""", """ Skyformation """ ]
  Fields = [
    """\d+\s+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)\s+[\w\-.]+\s+Skyformation""",
    """"event-name":"({alert_name}[^"]+)""",
    """"event-name":"({alert_type}[^"]+)""",
    """"classification":"({alert_type}[^"]+)""",
    """"severity":({alert_severity}[^",]+)""",
    """"file","name":"(|({file_path}({file_parent}[^"]*?)[\\\/]*({file_name}[^\\\/"]+?(\.({file_ext}[^\\\/\.\s"]+))?)))"""",
    """"source-device":\{[^\{\}]*?"name":"({dest_host}[\w\-.]+)""",
    """"source-device":\{[^\{\}]*?"ip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"source-device":\{[^\{\}]*?"mac-address":"({dest_mac}[^\s"]+)""",

    """"hash-value":"({sha256_sum}[^"]+)""",
    """"file_size":({bytes}\d+)""",
  ]
  DupFields = [ "file_name->malware_file_name" ]
}
```