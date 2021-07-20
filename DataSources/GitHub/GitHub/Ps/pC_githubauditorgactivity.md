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
    """"start":({time}\d{1,100}),""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({host}\S+)\s{1,100}github_audit:""",
    """"{1,20}actor"{1,20}:"{1,20}({user}[^"]{1,2000})""",
    """"{1,20}user"{1,20}:"{1,20}({resource}[^"]{1,2000})""",
    """"{1,20}action"{1,20}:"{1,20}({activity}[^"]{1,2000})""",
    """"{1,20}actor_ip"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
    """"{1,20}org"{1,20}:"{1,20}({object}[^"]{1,2000})""",
    """({app}github)"""
  ]
}
```