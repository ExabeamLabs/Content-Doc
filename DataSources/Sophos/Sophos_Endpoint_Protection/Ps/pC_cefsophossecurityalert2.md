#### Parser Content
```Java
{
Name = cef-sophos-security-alert-2
  Conditions = [ """|sophos|sophos central|""", """|Event::Endpoint::WebFilteringBlocked|""" ]

cef-sophos-security-alert = {
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|sophos|sophos central|""", """|Event::Endpoint::Threat::Detected|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\Wrt=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CEF:([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})""",
    """description=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){5}({additional_info}Access has been blocked to '({target}[^']{1,2000})' as '({alert_name}[^']{1,2000})'[^\|]{0,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({additional_info}Malicious traffic detected:\s{0,100}'({alert_name}[^']{1,2000})' at '({malware_url}[^']{1,2000})'[^\|]{0,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({additional_info}Malware detected:\s{0,100}'({alert_name}[^']{1,2000})' at '({malware_url}[^']{1,2000})'[^\|]{0,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({additional_info}'[^']{1,2000}'\s{1,100}({alert_name}[^'\|]{1,2000}?) in [^\|]{0,2000})""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
    """\Wdhost=({src_host}[\w\-.]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wsuser=((({dest_host}[^\s\\]{1,2000})\\+)?({user}[^\s\\,]{1,2000}),?|(n\/a|({user_fullname}[^\\]{1,2000}?)))\s{1,100}(\w+=|$)""",
    """\Wid=({alert_id}[^\s]{1,2000})""",
    """source_info_ip=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """filePath=({process}(([^"]{1,2000})?[\\\/])?({process_name}[^\\\/\s]{1,2000}))\s{1,100}(\w+=|$)""",
  
}
```