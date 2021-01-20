#### Parser Content
```Java
{
Name = stealthwatch-network-alert-2
  Vendor = Cisco
  Product = Cisco StealthWatch (Lancope)
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """StealthWatch[""", """]: """ , """Z;""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+Z);[^;]*;(|({alert_name}[^;]+));[^;]*;(|({alert_type}[^;]+));({alert_severity}[^;]+);[^;]*;(|({additional_info}[^;]+));(|0.0.0.0|({src_ip}[A-Fa-f:\d.]+));(|({src_host}[\w\-.]+));(|0.0.0.0|({dest_ip}[A-Fa-f:\d.]+));(|({dest_host}[\w\-.]+));([^;]*;){3}(|({host}[A-Fa-f:\d.]+));(|({=host}[\w\-.]+));""",
  ]
}
```