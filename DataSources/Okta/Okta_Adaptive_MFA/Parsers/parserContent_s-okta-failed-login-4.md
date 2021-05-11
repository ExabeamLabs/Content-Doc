#### Parser Content
```Java
{
Name = s-okta-failed-login-4
    Vendor = Okta
    Product = Okta Adaptive MFA
    Lms = Splunk
    DataType = "failed-app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """Suspicious Activity""",""""published":"""]
    Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """"published":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
      """"ipAddress":\s{0,100}"({src_ip}[^"]+)"""",
      """({app}Okta)""",
      """requestClientApplication=({app}[^=]+?)\s{0,100}\w+=""",
      """AppInstance[^\}\{]+displayName":\s{0,100}"({app}[^"\}\{]+)"""",
      """\{[^\{]+?displayName":\s{0,100}"({app}[^"]+?)\s{0,100}"[^\}\{]+AppInstance""",
      """({alert_name}Suspicious Activity)[^=]+?objectType":\s{0,100}"({alert_type}[^"]+)"""",
      """message":\s{0,100}"({additional_info}[^"]+)"""",
      """message"{0,20}:\s{0,100}"{0,20}[^"]+?user:\s{0,100}(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))""", 
      """suser=((?i)(anonymous|system)|({user_email}[^@\s]+@({domain}[^\s@]+))|(({=domain}[^\\\s]+)\\+)?({user}[^\s]+))""",
      """({activity}(?i)(Sign-in Failed))""",
      """({outcome}Failed)""",
      """"targets":\s{0,100}\[\{[^\{\}]*?"displayName":\s{0,100}"({user_fullname}[^",\s]+\s{1,100}[^",]+)"[^\{\}]*?"objectType":\s{0,100}"User"""",
      """"targets":\s{0,100}\[\{[^\{\}]*?"objectType":\s{0,100}"User"[^\{\}]*?"displayName":\s{0,100}"({user_fullname}[^",]+\s{1,100}[^",]+)"""",
      """"targets"":\s{0,100}\[\{[^\{\}]*?""objectType"":\s{0,100}""User""[^\{\}]*?""displayName"":\s{0,100}""({user_lastname}[^,"]+),\s{0,100}({user_firstname}[^,"\}\]]+)"""",
    ]
    DupFields = [ "additional_info->failure_reason" ]
}
```