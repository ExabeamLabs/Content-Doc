#### Parser Content
```Java
{
Name = s-okta-app-activity
    Vendor = Okta
    Product = Okta Adaptive MFA
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """objectType": "app.""",""""actors":"""]
    Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",

  """"published":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
  """"ipAddress":\s{0,100}"({src_ip}[^"]{1,2000})"""",
  """targets.+?login":\s{0,100}"(({user_email}[^"\s@]{1,2000}@({domain}[^"\s@,]{1,2000}))|({user}[^"\s,@]{1,2000}))""",
        """AppInstance[^\}\{]{1,2000}displayName":\s{0,100}"({app}[^"]{1,2000})"""",
        """\{.+?displayName":\s{0,100}"({app}[^"]{1,2000})"[^\}\{]{1,2000}AppInstance""",
  """"objectType":\s{0,100}"app\.({activity}[^"]{1,2000})"""",
  """categories":\s{0,100}\["({activity}[^,"]{1,2000})""",
  """message":\s{0,100}"({additional_info}[^"]{1,2000}?)\s{0,100}"""",
        """"id":\s{0,100}"({user_agent}[^"]{1,2000})([^\}\{]{1,2000}"Client")""",
        """(Client"[^\}\{]{1,2000})"id":\s{0,100}"({user_agent}[^"]{1,2000})""",
        """requestUri":\s{0,100}"({request_uri}[^"]{1,2000}?)\s{0,100}"""",
    ]
}
```