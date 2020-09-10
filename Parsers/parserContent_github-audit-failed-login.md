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
    """"start":({time}\d+),""",
    """"+@timestamp"+:({time}\d+)""",
    """({host}\S+)\s+github_audit:""",
    """"+host"+:"+({host}[^"]+)""",
    """"+action"+:"+({activity}[^"]+)""",
    """"+user"+:"+({user}[^"]+)""",
    """"+actor_ip"+:"+({src_ip}[^"]+)""",
    """({app}github)"""
  ]
}
```