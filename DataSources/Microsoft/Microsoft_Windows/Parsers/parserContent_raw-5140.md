#### Parser Content
```Java
{
Name = raw-5140
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "epoch"
    Conditions = ["""A network share object was accessed""", """Account Name:"""]
    Fields = [
      """({event_name}A network share object was accessed)""",
      """({event_code}5140)""",
      """(::ffff:)?({host}[^\s=]+)\sMSWinEventLog""",
      """\sComputer=\s*(::ffff:)?({host}[^\s]*)""",
      """<Computer>(::ffff:)?({host}.+?)<\/Computer>""",
      """"system_name":"(::ffff:)?({host}[^"]+)"""",
      """"Hostname":"(::ffff:)?({host}[^"]+)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
      """\sTimeGenerated=({time}\d+)""",
      """({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+)""",
      """\w+\s*\d+\s\d+:\d+:\d+\s+(::ffff:)?({host}[\w\-.]+)""",
      """Logon ID:\s*((\\)[rnt])*({logon_id}\S+?)((\\)[rnt])*\s*Network Information:""",
      """Account Name:\s*((\\)[rnt])*({user}\S+?)((\\)[rnt])*\s*Account Domain:""",
      """Account Domain:\s*((\\)[rnt])*({domain}\S+?)((\\)[rnt])*\s*Logon ID:""",
      """Object Type:\s*((\\)[rnt])*({file_type}.+?)((\\)[rnt])*\s*Source Address:""",
      """Source Address:\s*((\\)[rnt])*(::ffff:)?({src_ip}\S+?)((\\)[rnt])*\s*Source Port:""",
      """({accesses}Read)""",
      """Share Name:\s*((\\)[rnt])*(?:\\\\\*\\)?({share_name}.+?)((\\)[rnt])*\s*Share Path:""",
      """Share Path:\s*((\\)[rnt])*(?:\\+\?+)?(?:\s*|({share_path}(({d_parent}.+?)\\)?(|({d_name}[^\\]+?)))\\?)((\\)[rnt])*\s*Access Request Information:""",
      """\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))"""
    ]
  }
```