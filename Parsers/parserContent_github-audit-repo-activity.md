#### Parser Content
```Java
{
Name = github-audit-repo-activity
  Vendor = GitHub
  Product = GitHub
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ "github_audit", """action":"repo""" ]
  Fields = [
    """"created_at":({time}\d+),""",
    """"start":({time}\d+),""",
    """exabeam_host=({host}[\w.\-]+)""",
    """({host}\S+)\s+github_audit:""",
    """"+actor"+:"+({user}[^"]+)""",
    """"+action"+:"+({activity}[^"]+)""",
    """"+actor_ip"+:"+({src_ip}[^"]+)""",
    """"+repo"+:"+({object}[^"]+)""",
    """({app}github)"""
  ]
}
```