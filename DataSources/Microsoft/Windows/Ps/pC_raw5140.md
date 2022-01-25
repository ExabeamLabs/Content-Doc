#### Parser Content
```Java
{
Name = raw-5140
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "epoch"
    Conditions = ["""A network share object was accessed""", """Account Name:"""]
    Fields = [
      """({event_name}A network share object was accessed)""",
      """({event_code}5140)""",
      """(::ffff:)?({host}[^\s=]{1,2000})\sMSWinEventLog""",
      """\sComputer(Name)?=\s{0,100}(::ffff:)?({host}[^\s]{0,2000})""",
      """Computer=\s{0,100}(::ffff:)?"({host}[\w\-.]{1,2000})"""",
      """<Computer>(::ffff:)?({host}[^<]{1,2000}?)<\/Computer>""",
      """"system_name":"(::ffff:)?({host}[^"]{1,2000})"""",
      """"Hostname":"(::ffff:)?({host}[^"]{1,2000})"""",
      """({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(AM|PM))""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
      """\sTimeGenerated=({time}\d{1,100})""",
      """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100})""",
      """(?i)\w+\s{0,100}\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(am|pm|({host}[\w\-.]{1,2000}))""",
      """Logon ID:\s{0,100}((\\)[rnt])*({logon_id}\S+?)((\\)[rnt])*\s{0,100}Network Information:""",
      """Account Name:\s{0,100}((\\)[rnt])*({user}\S+?)((\\)[rnt])*\s{0,100}Account Domain:""",
      """Account Domain:\s{0,100}((\\)[rnt])*({domain}\S+?)((\\)[rnt])*\s{0,100}Logon ID:""",
      """Object Type:\s{0,100}((\\)[rnt])*({file_type}[^:]{1,2000}?)((\\)[rnt])*\s{0,100}Source Address:""",
      """Source Address:\s{0,100}((\\)[rnt])*(::ffff:)?({src_ip}\S+?)((\\)[rnt])*\s{0,100}Source Port:""",
      """({accesses}Read)""",
      """Share Name:\s{0,100}((\\)[rnt])*(?:\\\\\*\\)?({share_name}[^:]{1,2000}?)((\\)[rnt])*\s{0,100}Share Path:""",
      """Share Path:\s{0,100}((\\)[rnt])*(?:\\+\?+)?(?:\s{0,100}|({share_path}(({d_parent}[^"]{1,2000}?)\\)?(|({d_name}[^\\]{1,2000}?)))\\?)((\\)[rnt])*\s{0,100}Access Request Information:""",
      """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]{1,2000})))"""
    ]
    DupFields = ["host->dest_host"]
  

}
```