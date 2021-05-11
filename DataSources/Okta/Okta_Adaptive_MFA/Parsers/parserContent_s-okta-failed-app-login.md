#### Parser Content
```Java
{
Name = s-okta-failed-app-login
    Vendor = Okta
    Product = Okta Adaptive MFA
    Lms = Splunk
    DataType = "failed-app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """Sign-in Failure""",""""published":"""]
    Fields = [
      """"published":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """exabeam_host=({host}[\w\-.]+)""",
      """"ipAddress":\s{0,100}"({src_ip}[^"]+)"""",
      """"login":\s{0,100}"({user}[^"]+)"""",
      """"login":\s{0,100}"[^@]+@({domain}[^"]+)"""",
      """Sign-(I|i)n Failed\s{0,100}-\s{0,100}({failure_reason}[^"]+)"""",
      """AppInstance[^\}\{]+displayName":\s{0,100}"({app}[^"]+)"""",
      """\{.+?displayName":\s{0,100}"({app}[^"]+)"[^\}\{]+AppInstance""",
      """targets":\s{0,100}\[\{"displayName":\s{0,100}"({app}[^"]+)"""",
      """"id":\s{0,100}"({user_agent}[^"]+)([^\}\{]+"Client")""",
      """(Client"[^\}\{]+)"id":\s{0,100}"({user_agent}[^"]+)"""
    ]
}
```