#### Parser Content
```Java
{
Name = s-okta-failed-login-4
    Vendor = Okta
    Product = Okta MFA
    Lms = Splunk
    DataType = "failed-app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """Suspicious Activity""",""""published":"""]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """"published":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
      """"ipAddress":\s*"({src_ip}[^"]+)"""",
      """"login":\s*"({user}[^"@\s]+)"""",
      """"login":\s*"({user_email}[^"@\s]+@[^"\s@]+)"""",
      """"login":\s*"[^@]+@({domain}[^"]+)"""",
      """({app}Okta)""",
      """AppInstance[^\}\{]+displayName":\s*"({app}[^"\}\{]+)"""",
      """\{.+?displayName":\s*"({app}[^"]+?)\s*"[^\}\{]+AppInstance""",
      """({alert_name}Suspicious Activity).+?objectType":\s*"({alert_type}[^"]+)"""",
     """message":\s*"({additional_info}[^"]+)"""",
     """message"*:\s*"*[^"]+?user:\s*(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))""", 
      """({activity}Sign-in Failed)""",
      """({outcome}Failed)""",
      """"targets":\s*\[\{[^\{\}]*?"displayName":\s*"({user_fullname}[^",\s]+\s+[^",]+)"[^\{\}]*?"objectType":\s*"User"""",
      """"targets":\s*\[\{[^\{\}]*?"objectType":\s*"User"[^\{\}]*?"displayName":\s*"({user_fullname}[^",]+\s+[^",]+)"""",
      """"targets"":\s*\[\{[^\{\}]*?""objectType"":\s*""User""[^\{\}]*?""displayName"":\s*""({user_lastname}[^,"]+),\s*({user_firstname}[^,"\}\]]+)"""",
    ]
    DupFields = [ "additional_info->failure_reason" ]
}
```