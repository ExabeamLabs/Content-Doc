#### Parser Content
```Java
{
Name = github-audit-team-activity
  Vendor = GitHub
  Product = GitHub
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ "github_audit", """action":"team""" ]
  Fields = [
    """"start":({time}\d{1,100}),""",
    """exabeam_host=({host}[\w.\-]+)""",
    """exabeam_host=({user}[\w.\-]+)""",
    """({host}\S+)\s{1,100}github_audit:""",
    """"{1,20}actor"{1,20}:"{1,20}({user}[^"]+)""",
    """"{1,20}action"{1,20}:"{1,20}({activity}[^"]+)""",
    """"{1,20}user"{1,20}:"{1,20}({resource}[^"]+)""",
    """"{1,20}actor_ip"{1,20}:"{1,20}({src_ip}[^"]+)""",
    """"{1,20}team"{1,20}:"{1,20}({object}[^"]+)""",
    """"{1,20}repo"{1,20}:"{1,20}({resource}[^"]+)""",
    """({additional_info}"{1,20}ldap_mapped"{1,20}:[^,]+)""",
    """({app}github)"""
  ]
}
```