#### Parser Content
```Java
{
Name = f5-afm-alert
  Vendor = F5
  Product = F5 BIG-IP Advanced Firewall Module (AFM)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """device_vendor="F5"""", """device_product="Advanced Firewall Module"""", """dos_attack_name=""" ]
  Fields = [
    """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}(\+|-)\d{2}:\d{2})\s({host}[\w.-]{1,2000})""",
    """dos_attack_name="({alert_name}[^"]{1,2000})"""",
    """\Werrdefs_msg_name="({event_name}[^"]{1,2000})""",
    """severity="({alert_severity}[^"]{1,2000})""""
  ]


}
```