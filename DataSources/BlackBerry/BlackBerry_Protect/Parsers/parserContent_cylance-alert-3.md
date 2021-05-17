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
    """\d{1,100}\s{1,100}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)\s{1,100}[\w\-.]{1,2000}\s{1,100}Skyformation""",
    """"event-name":"({alert_name}[^"]{1,2000})""",
    """"event-name":"({alert_type}[^"]{1,2000})""",
    """"classification":"({alert_type}[^"]{1,2000})""",
    """"severity":({alert_severity}[^",]{1,2000})""",
    """"file","name":"(|({file_path}({file_parent}[^"]{0,2000}?)[\\\/]{0,2000}({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^\\\/\.\s"]{1,2000}))?)))"""",
    """"source-device":\{[^\{\}]{0,2000}?"name":"({dest_host}[\w\-.]{1,2000})""",
    """"source-device":\{[^\{\}]{0,2000}?"ip":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"source-device":\{[^\{\}]{0,2000}?"mac-address":"({dest_mac}[^\s"]{1,2000})""",

    """"hash-value":"({sha256_sum}[^"]{1,2000})""",
    """"file_size":({bytes}\d{1,100})""",
  ]
  DupFields = [ "file_name->malware_file_name" ]
}
```