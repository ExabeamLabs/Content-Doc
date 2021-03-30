#### Parser Content
```Java
{
Name = l-4673
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["<EventID>4673</EventID>", "A privileged service was called", "Privileges:"]
    Fields = [
      """({event_name}A privileged service was called)""",
      """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({outcome}Information|Audit Success|Success Audit|Failure Audit|Audit Failure)""",
      """<Computer>({host}[^<]+)</Computer>""",
	  """<EventID>({event_code}[^<]+)</EventID>""",
      """Process Name:\s*(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))\s*Service Request Information:""",
      """Account Name:\s*({user}.+?)\s*Account Domain:""",
      """Account Domain:\s*({domain}.+?)\s*Logon ID:""",
      """Logon ID:\s*({logon_id}.+?)\s*Service:""",
      """Server:\s*({object_server}.+?)\s*Service Name""",
      """Privileges:\s*({privileges}.+?)\s*(<|$)""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```