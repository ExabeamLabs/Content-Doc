#### Parser Content
```Java
{
Name = f5-big-ip-authentication-successful
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490265""", """ BIG-IP """, """have received SAML Assertion from IdP""" ]
  Fields = [
    """:\d\d:\d\d ({host}[\w.-]{1,2000})\s""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """value \(({user}[^\)]{1,2000}?)\)""",
    """({app}BIG-IP)""",
    """({event_name}received SAML Assertion from IdP)""",
    """({event_code}01490265)""",
    """({auth_method}SAML)""",
    """({additional_info}BIG-IP[^"]{1,2000}?)\s{0,20}$"""
  ]


}
```