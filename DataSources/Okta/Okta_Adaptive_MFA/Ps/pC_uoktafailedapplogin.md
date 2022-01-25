#### Parser Content
```Java
{
Name = u-okta-failed-app-login
    Vendor = Okta
    Product = Okta Adaptive MFA
    Lms = Sumo
    DataType = "failed-app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """|OKTA|OKTA Identity Provider|""","""|Sign-in Failure|"""]
    Fields = [
  """start=({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}:\d{1,100})""",
        """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """instance=({host}[^,]{1,2000})""",
        """user:\s({user}[^,]{1,2000})""",
        """msg=Sign-In Failed - ({failure_reason}[^:,]{1,2000})""",
        """cs3=({user_agent}.+?), \w+=""",
        """({app}Okta)"""
    ]


}
```