#### Parser Content
```Java
{
Name = cef-netskope-alert-compromise
  Vendor = Netskope
  Product = Netskope Active Platform
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"Compromised Credential"""", """destinationServiceName=Netskope""", """|security-threat-detected|""", """"type":"breach"""" ]
 Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"timestamp":({time}\d+)""",
    """"user":"(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))"""",
    """"_id":"({alert_id}[^"]+)""",
    """"category":"(n\/a|({threat_category}[^"]+))""",
    """"alert_type"+:"+({alert_name}[^"]+)""",
    """"hostname":"({src_host}[^"]+)""",
    """security-threat-detected\|({alert_severity}\d+)""",
    """"alert_name":"({additional_info}[^"]+)""",
    """"type":"({alert_type}[^"]+)""",
    """"from_user":"({sender}[^",]+)"""",
    """"to_user":"({recipients}({recipient}[^"\s@;,]+@({external_domain}[^"\s@,]+))[^"]*)"""",
    """"url":\s*"(?!\w+:\/+)({file_path}(({file_parent}[^",]*?)[\/]+)?({file_name}[^"\/,]+?(\.({file_ext}[^"\/,\.]+))?)?)\s*"""",
    """"sha256":"({sha256}[^",]+)"""",
    """"site":"({app}[^",]+)""""
  ]
}
```