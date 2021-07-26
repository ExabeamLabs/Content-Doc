#### Parser Content
```Java
{
Name = raw-5145
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""A network share object was checked to see whether client can be granted desired access""", """Account Name:"""]
    Fields = [
      """({event_name}A network share object was checked to see whether client can be granted desired access)""",
      """({event_code}5145)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
      """({host}[\w\-.]{1,2000})\s{1,100}(?i)((audit|success)( |_)(success|audit))""",
      """Logon ID:\s{0,100}((\\)[rnt])*({logon_id}\S+?)((\\)[rnt])*\s{0,100}Network Information:""",
      """Account Name:\s{0,100}((\\)[rnt])*({user}\S+?)((\\)[rnt])*\s{0,100}Account Domain:""",
      """Account Domain:\s{0,100}((\\)[rnt])*({domain}\S+?)((\\)[rnt])*\s{0,100}Logon ID:""",
      """Object Type:\s{0,100}((\\)[rnt])*({file_type}[^:]{1,2000}?)((\\)[rnt])*\s{0,100}Source Address:""",
      """Source Address:\s{0,100}((\\)[rnt])*(::1|({src_ip}[A-Fa-f:\d.]{1,2000}?))((\\)[rnt])*\s{0,100}Source Port:""",
      """Share Name:\s{0,100}((\\)[rnt])*(?:\\\\\*\\)?({share_name}[^=]{1,2000}?)((\\)[rnt])*\s{0,100}Share Path:""",
      """Share Path:\s{0,100}((\\)[rnt])*(?:[\\\?]{1,2000})?(?:\s{0,100}|({share_path}(({d_parent}[^=]{1,2000}?)\\)?(|({d_name}[^\\]{0,2000}?)))\\?)((\\)[rnt])*\s{0,100}Relative Target Name:""",
      """Relative Target Name:\s{0,100}((\\)[rnt])*\\?(?:\s{0,100}|(?:({f_parent}[^=]{1,2000}?)\\)?(|({file_name}[^\\:\/]{1,2000}?(?:\.({file_ext}[^\.]{1,2000}?))?))(?:\\HEAD|:[^=]{1,2000}?|\\|\s|((\\)[rnt])*)\s{0,100})Access Request Information:""",
      """Accesses:[^=]{0,2000}({accesses}SYNCHRONIZE|Execute|Traverse|Read|READ|WRITE_DAC|WRITE_OWNER|WriteAttributes|WriteEA|WriteData|AppendData|delete|Delete)[^=]{0,2000}Access Check Results:""",
      """Access Check Results:\s{0,100}({outcome}-)\s""",
      """Access Check Results:[^=]{0,2000}({outcome}Granted|Denied)\s{1,100}by""",
    ]
    DupFields = ["host->dest_host"]
  }
```