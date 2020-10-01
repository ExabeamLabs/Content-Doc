#### Parser Content
```Java
{
Name = sfdc-app-login
  Vendor = Salesforce
  Product = Salesforce
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"LoginUrl"""",""""login.salesforce.com"""" ]
  Fields = [
    """({app}salesforce)""",
    """LoginTime":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}\S+)""",
    """Status":\s*"({outcome}[^"]+)""",
    """LoginType":\s*"({login_type}[^"]+)""",
    """Browser":\s*"({browser}[^"]+)""",
    """UserId":\s*"({user}[^"]+)""",
    """SourceIp":\s*"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Platform":\s*"({os}[^"]+)""",
    """Application":\s*"({protocol}[^"]+)""",
  ]
}
```