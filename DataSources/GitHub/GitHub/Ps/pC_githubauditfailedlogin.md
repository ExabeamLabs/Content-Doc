#### Parser Content
```Java
{
Name = github-audit-failed-login
  Vendor = GitHub
  Product = GitHub
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "epoch"
  Conditions = [ "failed_login", "github_audit" ]
  Fields = [
    """"start":({time}\d{1,100}),""",
    """"{1,20}@timestamp"{1,20}:({time}\d{1,100})""",
    """({host}\S+)\s{1,100}github_audit:""",
    """"{1,20}host"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"{1,20}action"{1,20}:"{1,20}({activity}[^"]{1,2000})""",
    """"{1,20}user"{1,20}:"{1,20}({user}[^"]{1,2000})""",
    """"{1,20}actor_ip"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
    """({app}github)"""
  ]
}
```