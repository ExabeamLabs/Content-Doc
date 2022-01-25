#### Parser Content
```Java
{
Name = s-github-audit
  Vendor = GitHub
  Product = GitHub
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "repo_name", "github_audit" ]
  Fields = [
    """"{1,20}@timestamp"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"{1,20}hostname"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"{1,20}repo_name"{1,20}:"{1,20}({object}[^"]{1,2000})""",
    """"{1,20}program"{1,20}:"{1,20}({activity}[^"]{1,2000})""",
    """"{1,20}user_login"{1,20}:"{1,20}({user}[^"]{1,2000})""",
    """"{1,20}real_ip"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
    """"{1,20}pubkey_fingerprint"{1,20}:"{1,20}({fingerprint}[^"]{1,2000})""",
    """({app}github)"""
  ]
}
```