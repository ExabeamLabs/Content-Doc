#### Parser Content
```Java
{
Name = stealthwatch-network-alert-2
  Vendor = Cisco
  Product = Cisco Secure Network Analytics
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """StealthWatch[""", """]: """ , """Z;""" ]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z);[^;]{0,2000};(|({alert_name}[^;]{1,2000}));[^;]{0,2000};(|({alert_type}[^;]{1,2000}));({alert_severity}[^;]{1,2000});[^;]{0,2000};(|({additional_info}[^;]{1,2000}));(|0.0.0.0|({src_ip}[A-Fa-f:\d.]{1,2000}));(|({src_host}[\w\-.]{1,2000}));(|0.0.0.0|({dest_ip}[A-Fa-f:\d.]{1,2000}));(|({dest_host}[\w\-.]{1,2000}));([^;]{0,2000};){3}(|({host}[A-Fa-f:\d.]{1,2000}));(|({=host}[\w\-.]{1,2000}));""",
  ]
}
```