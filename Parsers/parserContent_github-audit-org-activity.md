#### Parser Content
```Java
{
Name = github-audit-org-activity
  Vendor = GitHub
  Product = GitHub
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ "github_audit", """action":"org""" ]
  Fields = [
    """"start":({time}\d+),""",
    """exabeam_host=({host}[\w.\-]+)""",
    """({host}\S+)\s+github_audit:""",
    """"+actor"+:"+({user}[^"]+)""",
    """"+user"+:"+({resource}[^"]+)""",
    """"+action"+:"+({activity}[^"]+)""",
    """"+actor_ip"+:"+({src_ip}[^"]+)""",
    """"+org"+:"+({object}[^"]+)""",
    """({app}github)"""
  ]
}
```