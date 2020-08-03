#### Parser Content
```Java
{
Name = s-okta-security-alert
    Vendor = Okta
    Product = Okta MFA
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """Suspicious Activity""",""""published":"""]
    Fields = [
  """"published":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
  """"ipAddress":\s*"({src_ip}[^"]+)"""",
  """"login":\s*"({user}[^"@\s]+)"""",
  """"login":\s*"({user_email}[^"@\s]+@[^"\s@]+)"""",
  """"login":\s*"[^@]+@({domain}[^"]+)"""",
        """AppInstance[^\}\{]+displayName":\s*"({app}[^"\}\{]+)"""",
        """\{.+?displayName":\s*"({app}[^"]+?)\s*"[^\}\{]+AppInstance""",
  """({alert_name}Suspicious Activity).+?objectType":\s*"({alert_type}[^"]+)"""",
  """message":\s*"({additional_info}[^"]+)""""
    ]
}
```