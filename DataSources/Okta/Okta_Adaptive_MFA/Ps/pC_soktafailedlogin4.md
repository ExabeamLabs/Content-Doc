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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """"published":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
      """"ipAddress":\s{0,100}"({src_ip}[^"]{1,2000})"""",
      """({app}Okta)""",
      """requestClientApplication=({app}[^=]{1,2000}?)\s{0,100}\w+=""",
      """AppInstance[^\}\{]{1,2000}displayName":\s{0,100}"({app}[^"\}\{]{1,2000})"""",
      """\{[^\{]{1,2000}?displayName":\s{0,100}"({app}[^"]{1,2000}?)\s{0,100}"[^\}\{]{1,2000}AppInstance""",
      """({alert_name}Suspicious Activity)[^=]{1,2000}?objectType":\s{0,100}"({alert_type}[^"]{1,2000})"""",
      """message":\s{0,100}"({additional_info}[^"]{1,2000})"""",
      """message"{0,20}:\s{0,100}"{0,20}[^"]{1,2000}?user:\s{0,100}(({user_email}[^"@]{1,2000}@[^"@]{1,2000})|({user}[^"]{1,2000}))""", 
      """suser=((?i)(anonymous|system)|({user_email}[^@\s]{1,2000}@({domain}[^\s@]{1,2000}))|(({=domain}[^\\\s]{1,2000})\\+)?({user}[^\s]{1,2000}))""",
      """({activity}(?i)(Sign-in Failed))""",
      """({outcome}Failed)""",
      """"targets":\s{0,100}\[\{[^\{\}]{0,2000}?"displayName":\s{0,100}"({user_fullname}[^",\s]{1,2000}\s{1,100}[^",]{1,2000})"[^\{\}]{0,2000}?"objectType":\s{0,100}"User"""",
      """"targets":\s{0,100}\[\{[^\{\}]{0,2000}?"objectType":\s{0,100}"User"[^\{\}]{0,2000}?"displayName":\s{0,100}"({user_fullname}[^",]{1,2000}\s{1,100}[^",]{1,2000})"""",
      """"targets"":\s{0,100}\[\{[^\{\}]{0,2000}?""objectType"":\s{0,100}""User""[^\{\}]{0,2000}?""displayName"":\s{0,100}""({user_lastname}[^,"]{1,2000}),\s{0,100}({user_firstname}[^,"\}\]]{1,2000})"""",
    ]
    DupFields = [ "additional_info->failure_reason" ]


}
```