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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",

  """"published":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
  """"ipAddress":\s{0,100}"({src_ip}[^"]+)"""",
  """targets.+?login":\s{0,100}"(({user_email}[^"\s@]+@({domain}[^"\s@,]+))|({user}[^"\s,@]+))""",
        """AppInstance[^\}\{]+displayName":\s{0,100}"({app}[^"]+)"""",
        """\{.+?displayName":\s{0,100}"({app}[^"]+)"[^\}\{]+AppInstance""",
  """"objectType":\s{0,100}"app\.({activity}[^"]+)"""",
  """categories":\s{0,100}\["({activity}[^,"]+)""",
  """message":\s{0,100}"({additional_info}[^"]+?)\s{0,100}"""",
        """"id":\s{0,100}"({user_agent}[^"]+)([^\}\{]+"Client")""",
        """(Client"[^\}\{]+)"id":\s{0,100}"({user_agent}[^"]+)""",
        """requestUri":\s{0,100}"({request_uri}[^"]+?)\s{0,100}"""",
    ]
}
```