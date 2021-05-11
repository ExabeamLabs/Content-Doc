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
    """LoginTime":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}\S+)""",
    """Status":\s{0,100}"({outcome}[^"]+)""",
    """LoginType":\s{0,100}"({login_type}[^"]+)""",
    """Browser":\s{0,100}"({browser}[^"]+)""",
    """UserId":\s{0,100}"({user}[^"]+)""",
    """SourceIp":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Platform":\s{0,100}"({os}[^"]+)""",
    """Application":\s{0,100}"({protocol}[^"]+)""",
  ]
}
```