#### Parser Content
```Java
{
Name = q-4662
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "adobject-operation"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=4662" ]
  Fields = [
    """Computer=\s{0,100}({host}[^\s]{0,2000})""",
    """EventID=({event_code}\d{1,100})""",
    """TimeGenerated=({time}\d{1,100})""",
    """Message=({event_name}.*?)\s{1,100}Subject:""",
    """Security ID:\s{0,100}({user_sid}\S+)\s{1,100}Account Name:""",
    """Account Name:\s{0,100}({user}\S+)\s{1,100}Account Domain:""",
    """Account Domain:\s{0,100}({domain}\S+)\s{1,100}Logon ID:""",
    """Logon ID:\s{0,100}({logon_id}\S+)\s{1,100}Object:""",
    """Object Server:\s{0,100}({object_class}\S.*?)\s{1,100}Object Type:""",
    """Object Type:\s{0,100}({object_type}\S+)\s{0,100}Object Name:""",
    """Object Name:\s{0,100}({object}\S.*?)\s{0,100}Handle ID:""",
    """Operation Type:\s{0,100}({activity_type}\S.*?)\s{0,100}Accesses:""",
    """Accesses:\s{0,100}({accesses}\S.*?)\s{0,100}Access Mask:""",
    """Properties:\s{0,100}({attributes}\S.*?)\s{0,100}Additional Information:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```