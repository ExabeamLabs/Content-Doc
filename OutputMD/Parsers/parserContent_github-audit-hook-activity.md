#### Parser Content
```Java
{
Name = github-audit-hook-activity
  Vendor = GitHub
  Product = GitHub
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ "github_audit", """action":"hook""" ]
  Fields = [
    """"start":({time}\d+),""",
    """exabeam_host=({host}[\w.\-]+)""",
    """({host}\S+)\s+github_audit:""",
    """"+actor"+:"+({user}[^"]+)""",
    """"+action"+:"+({activity}[^"]+)""",
    """"+repo"+:"+({resource}[^"]+)""",
    """({object}"+hook_id"+:[^,]+)""",
    """"+actor_ip"+:"+({src_ip}[^"]+)""",
    """"+config"+:\{({additional_info}.+?)\}
```