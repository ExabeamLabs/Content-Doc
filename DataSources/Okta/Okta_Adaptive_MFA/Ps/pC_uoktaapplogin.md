#### Parser Content
```Java
{
Name = u-okta-app-login
    Vendor = Okta
    Product = Okta Adaptive MFA
    Lms = Sumo
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """|OKTA|OKTA Identity Provider|""","""|Application Access|""","""msg=User performed single sign on to app"""]
    Fields = [
  """start=({time}\d\d\d\d\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}:\d{1,100})""",
  """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  """instance=({host}[^,]{1,2000})""",
        """duid=({user}[^,]{1,2000})""",
        """duid=[^@,]{1,2000}@({domain}[^,.]{1,2000})""",
        """destinationServiceName =({app}[^,]{1,2000})""",
        """cs3=({user_agent}.+?), \w+=""",
    ]


}
```