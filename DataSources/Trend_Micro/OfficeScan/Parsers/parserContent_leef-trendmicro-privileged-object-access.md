#### Parser Content
```Java
{
Name = leef-trendmicro-privileged-object-access
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = QRadar
  DataType = "privileged-object-access"
  TimeFormat = "epoch"
  Conditions = [ """LEEF:""", """|Trend Micro|Deep Security Agent|""", """cat=Log Inspection""", """An operation was attempted on a privileged object""", """(4674)""" ]
  Fields = [ 
    """exabeam_endTime=({time}\d{1,100})""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) LEEF:""",
    """dvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """shost=({src_host}[\w\-.]{1,2000})""",
    """({event_code}4674)""",
    """({event_name}An operation was attempted on a privileged object)""",
    """Security:\s{0,100}({outcome}[^\(]{1,2000})""",
    """Process Name:\s{0,100}(?: |({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?)))\s{0,100}Requested""",
    """Account Name:\s{0,100}(?:-|({user}.+?))\s{0,100}Account Domain:""",
    """Account Domain:\s{0,100}({domain}.+?)\s{0,100}Logon ID:""",
    """Logon ID:\s{0,100}({logon_id}.+?)\s{0,100}Object:""",
    """Object Server:\s{0,100}({object_server}.+?)\s{0,100}Object Type:""",
    """Object Type:\s{0,100}(?:-|({object_type}.+?))\s{0,100}Object Name:""",
    """Object Name:\s{0,100}(?:-|({object}.+?))\s{0,100}Object Handle""",
    """Desired Access:\s{0,100}({accesses}.+?)\s{0,100}Privileges:""",
    """Privileges:\s{0,100}({privileges}\S+)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```