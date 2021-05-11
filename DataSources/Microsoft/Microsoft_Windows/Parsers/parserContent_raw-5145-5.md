#### Parser Content
```Java
{
Name = raw-5145-5
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "epoch_sec"
    Conditions = ["""A network share object was checked to see whether client can be granted desired access""", """Account Name:""", "Microsoft-Windows-Security-Auditing", "Computer"]
    Fields = [
      """({event_name}A network share object was checked to see whether client can be granted desired access)""",
      """({event_code}5145)""",
      """Computer(Name)?\s{0,100}\\*"?(=|:|>)\s{0,100}"{0,20}({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
      """TimeGenerated=({time}\d{1,100})""",
      """Microsoft-Windows-Security-Auditing.+?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Logon ID:\s{0,100}((\\)[rnt])*({logon_id}\S+?)((\\)[rnt])*\s{0,100}Network Information:""",
      """Account Name:\s{0,100}((\\)[rnt])*({user}\S+?)((\\)[rnt])*\s{0,100}Account Domain:""",
      """Account Domain:\s{0,100}((\\)[rnt])*({domain}\S+?)((\\)[rnt])*\s{0,100}Logon ID:""",
      """Object Type:\s{0,100}((\\)[rnt])*({file_type}.+?)((\\)[rnt])*\s{0,100}Source Address:""",
      """Source Address:\s{0,100}((\\)[rnt])*(::1|({src_ip}[A-Fa-f:\d.]+?))((\\)[rnt])*\s{0,100}Source Port:""",
      """Share Name:\s{0,100}((\\)[rnt])*(?:\\\\\*\\)?({share_name}.+?)((\\)[rnt])*\s{0,100}Share Path:""",
      """Share Path:\s{0,100}((\\)[rnt])*(?:[\\\?]+)?(?:\s{0,100}|({share_path}(({d_parent}.+?)\\)?(|({d_name}[^\\]*?)))\\?)((\\)[rnt])*\s{0,100}Relative Target Name:""",
      """Relative Target Name:\s{0,100}((\\)[rnt])*\\?(?:\s{0,100}|(?:({f_parent}.+?)\\)?(|({file_name}[^\\:\/]+?(?:\.({file_ext}[^\.]+?))?))(?:\\HEAD|:.+?|\\|\s|((\\)[rnt])*)\s{0,100})Access Request Information:""",
      """Accesses:.*({accesses}SYNCHRONIZE|Execute|Traverse|Read|READ|WRITE_DAC|WRITE_OWNER|WriteAttributes|WriteEA|WriteData|AppendData|delete|Delete).*Access Check Results:""",
      """Access Check Results:\s{0,100}({outcome}-)\s""",
      """Access Check Results:.*({outcome}Granted|Denied)\s{1,100}by""",
    ]
    DupFields = ["host->dest_host"]
  }
```