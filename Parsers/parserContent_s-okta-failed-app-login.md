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
      """"published":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
      """exabeam_host=({host}[\w\-.]+)""",
      """"ipAddress":\s*"({src_ip}[^"]+)"""",
      """"login":\s*"({user}[^"]+)"""",
      """"login":\s*"[^@]+@({domain}[^"]+)"""",
      """Sign-(I|i)n Failed\s*-\s*({failure_reason}[^"]+)"""",
      """AppInstance[^\}\{]+displayName":\s*"({app}[^"]+)"""",
      """\{.+?displayName":\s*"({app}[^"]+)"[^\}\{]+AppInstance""",
      """targets":\s*\[\{"displayName":\s*"({app}[^"]+)"""",
      """"id":\s*"({user_agent}[^"]+)([^\}\{]+"Client")""",
      """(Client"[^\}\{]+)"id":\s*"({user_agent}[^"]+)"""
    ]
}
```