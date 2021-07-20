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
    """"created_at":({time}\d{1,100}),""",
    """"start":({time}\d{1,100}),""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({host}\S+)\s{1,100}github_audit:""",
    """"{1,20}actor"{1,20}:"{1,20}({user}[^"]{1,2000})""",
    """"{1,20}action"{1,20}:"{1,20}({activity}[^"]{1,2000})""",
    """"{1,20}actor_ip"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
    """"{1,20}repo"{1,20}:"{1,20}({object}[^"]{1,2000})""",
    """({app}github)"""
  ]
}
```