#### Parser Content
```Java
{
Name = okta-app-login-1
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Start New Session""", """"tenantHost":""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"userAgent":\s{0,100}"({user_agent}[^"]{1,2000})""",
    """"requestTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"deviceType":\s{0,100}"(login_type)""",
    """"systemAccount":\s{0,100}";*({user}[^;"]{1,2000})""",
    """"tenantHost":\s{0,100}"({app}[^"]{1,2000})""",
    """"activityAction":\s{0,100}"({activity}[^"]{1,2000})""",
    """"ipAddress":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"target":\s{0,100}\{[^\}]{0,2000}"descriptor":\s{0,100}"({user}[^\/"]{1,2000}?)\s{0,100}\/\s{0,100}({user_fullname}[^"]{1,2000})""",
  ]


}
```