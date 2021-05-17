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
      """exabeam_host=({host}[\w\-.]{1,2000})""",
      """"ipAddress":\s{0,100}"({src_ip}[^"]{1,2000})"""",
      """"login":\s{0,100}"({user}[^"]{1,2000})"""",
      """"login":\s{0,100}"[^@]{1,2000}@({domain}[^"]{1,2000})"""",
      """Sign-(I|i)n Failed\s{0,100}-\s{0,100}({failure_reason}[^"]{1,2000})"""",
      """AppInstance[^\}\{]{1,2000}displayName":\s{0,100}"({app}[^"]{1,2000})"""",
      """\{.+?displayName":\s{0,100}"({app}[^"]{1,2000})"[^\}\{]{1,2000}AppInstance""",
      """targets":\s{0,100}\[\{"displayName":\s{0,100}"({app}[^"]{1,2000})"""",
      """"id":\s{0,100}"({user_agent}[^"]{1,2000})([^\}\{]{1,2000}"Client")""",
      """(Client"[^\}\{]{1,2000})"id":\s{0,100}"({user_agent}[^"]{1,2000})"""
    ]
}
```