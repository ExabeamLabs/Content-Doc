#### Parser Content
```Java
{
Name = raw-5140
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "epoch_sec"
    Conditions = ["""A network share object was accessed""", """Account Name:"""]
    Fields = [
      """({event_name}A network share object was accessed)""",
      """({event_code}5140)""",
      """\s({host}[^\s]+)\sMSWinEventLog""",
      """\sComputer=\s*({host}[^\s]*)""",
      """<Computer>({host}.+?)<\/Computer>""",
      """"system_name":"({host}[^"]+)"""",
      """"Hostname":"({host}[^"]+)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
      """\sTimeGenerated=({time}\d+)""",
      """Logon ID:\s*((\\)[rnt])*({logon_id}\S+?)((\\)[rnt])*\s*Network Information:""",
      """Account Name:\s*((\\)[rnt])*({user}\S+?)((\\)[rnt])*\s*Account Domain:""",
      """Account Domain:\s*((\\)[rnt])*({domain}\S+?)((\\)[rnt])*\s*Logon ID:""",
      """Object Type:\s*((\\)[rnt])*({file_type}.+?)((\\)[rnt])*\s*Source Address:""",
      """Source Address:\s*((\\)[rnt])*({src_ip}\S+?)((\\)[rnt])*\s*Source Port:""",
      """({accesses}Read)""",
      """Share Name:\s*((\\)[rnt])*(?:\\\\\*\\)?({share_name}.+?)((\\)[rnt])*\s*Share Path:""",
      """Share Path:\s*((\\)[rnt])*(?:\\+\?+)?(?:\s*|({share_path}(({d_parent}.+?)\\)?(|({d_name}[^\\]+?)))\\?)((\\)[rnt])*\s*Access Request Information:""",
    ]
    DupFields = ["host->dest_host"]
  }
```