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
      """Process Name:\s{0,100}(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))\s{0,100}Service Request Information:""",
      """Account Name:\s{0,100}({user}[^=]+?)\s{0,100}Account Domain:""",
      """Account Domain:\s{0,100}({domain}[^=]+?)\s{0,100}Logon ID:""",
      """Logon ID:\s{0,100}({logon_id}.+?)\s{0,100}Service:""",
      """Server:\s{0,100}({object_server}[^=]+?)\s{0,100}Service Name""",
      """Privileges:\s{0,100}({privileges}[^<>\s"=]+)""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```