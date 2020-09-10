#### Parser Content
```Java
{
Name = s-okta-app-activity
    Vendor = Okta
    Product = Okta MFA
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """objectType": "app.""",""""actors":"""]
    Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",

  """"published":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
  """"ipAddress":\s*"({src_ip}[^"]+)"""",
  """"login":\s*"({user}[^"\s@]+)"""",
  """"login":\s*"({user_email}[^"\s@]+@[^"\s@]+)"""",
  """"login":\s*"[^@]+@({domain}[^"]+)"""",
        """AppInstance[^\}\{]+displayName":\s*"({app}[^"]+)"""",
        """\{.+?displayName":\s*"({app}[^"]+)"[^\}\{]+AppInstance""",
  """"objectType":\s*"app\.({activity}[^"]+)"""",
  """categories":\s*\["({activity}[^,"]+)""",
  """message":\s*"({additional_info}[^"]+?)\s*"""",
        """"id":\s*"({user_agent}[^"]+)([^\}\{]+"Client")""",
        """(Client"[^\}\{]+)"id":\s*"({user_agent}[^"]+)""",
        """requestUri":\s*"({request_uri}[^"]+?)\s*"""",
    ]
}
```