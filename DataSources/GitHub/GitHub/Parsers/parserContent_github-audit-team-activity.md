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
    """"start":({time}\d+),""",
    """exabeam_host=({host}[\w.\-]+)""",
    """exabeam_host=({user}[\w.\-]+)""",
    """({host}\S+)\s+github_audit:""",
    """"+actor"+:"+({user}[^"]+)""",
    """"+action"+:"+({activity}[^"]+)""",
    """"+user"+:"+({resource}[^"]+)""",
    """"+actor_ip"+:"+({src_ip}[^"]+)""",
    """"+team"+:"+({object}[^"]+)""",
    """"+repo"+:"+({resource}[^"]+)""",
    """({additional_info}"+ldap_mapped"+:[^,]+)""",
    """({app}github)"""
  ]
}
```