#### Parser Content
```Java
{
Name = cef-sophos-security-alert-41
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Syslog
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """Event::Endpoint::CorePuaDetection""", """PUA detected:""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """rt=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)""",
    """source_info_ip=({src_ip}[a-fA-F\d:.]{1,2000})""",
    """\sid=({alert_id}[^\s]{1,2000})\s""",
    """dhost=({dest_host}[^$\s]{1,2000}?)\s{0,100}$""",
    """Event::Endpoint::CorePuaDetection\|[^\|]{1,2000}\|({alert_severity}\d{1,100})\|""",
    """Event::Endpoint::CorePuaDetection\|({additional_info}[^\|]{1,2000})\|""",
    """threat=({alert_name}[^=]{1,2000}?)\s\w+=""",
    """({alert_type}Event::Endpoint::CorePuaDetection)""",
    """suser=(({user_fullname}({user_lastname}[^,]{1,2000}),\s({user_firstname}[^=\(]{1,2000}?)\s\([^\)]{1,2000}\))|(({domain}[^\\\s=]{1,2000})\\{1,20})({user}[^\s=]{1,2000}?)|({user_email}[^@]{1,2000}@[^@\s=]{1,2000}?))\s\w+=""",
    """PUA detected: '[^']{1,2000}' at '({malware_url}[^']{1,2000})'"""
  ]


}
```