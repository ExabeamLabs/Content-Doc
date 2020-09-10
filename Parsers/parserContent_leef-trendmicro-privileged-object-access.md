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
    """exabeam_endTime=({time}\d+)""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) LEEF:""",
    """dvc=({host}[A-Fa-f:\d.]+)""",
    """shost=({src_host}[\w\-.]+)""",
    """({event_code}4674)""",
    """({event_name}An operation was attempted on a privileged object)""",
    """Security:\s*({outcome}[^\(]+)""",
    """Process Name:\s*(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))\s*Requested""",
    """Account Name:\s*(?:-|({user}.+?))\s*Account Domain:""",
    """Account Domain:\s*({domain}.+?)\s*Logon ID:""",
    """Logon ID:\s*({logon_id}.+?)\s*Object:""",
    """Object Server:\s*({object_server}.+?)\s*Object Type:""",
    """Object Type:\s*(?:-|({object_type}.+?))\s*Object Name:""",
    """Object Name:\s*(?:-|({object}.+?))\s*Object Handle""",
    """Desired Access:\s*({accesses}.+?)\s*Privileges:""",
    """Privileges:\s*({privileges}\S+)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```