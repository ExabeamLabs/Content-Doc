#### Parser Content
```Java
{
Name = q-4662
  Vendor = Microsoft Windows
  Lms = QRadar
  DataType = "adobject-operation"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=4662" ]
  Fields = [
    """Computer=\s*({host}[^\s]*)""",
    """EventID=({event_code}\d+)""",
    """TimeGenerated=({time}\d+)""",
    """Message=({event_name}.*?)\s+Subject:""",
    """Security ID:\s*({user_sid}\S+)\s+Account Name:""",
    """Account Name:\s*({user}\S+)\s+Account Domain:""",
    """Account Domain:\s*({domain}\S+)\s+Logon ID:""",
    """Logon ID:\s*({logon_id}\S+)\s+Object:""",
    """Object Server:\s*({object_server}\S.*?)\s+Object Type:""",
    """Object Type:\s*({object_class}\S+)\s*Object Name:""",
    """Object Name:\s*({object}\S.*?)\s*Handle ID:""",
    """Operation Type:\s*({activity_type}\S.*?)\s*Accesses:""",
    """Accesses:\s*({accesses}\S.*?)\s*Access Mask:""",
    """Properties:\s*({attributes}\S.*?)\s*Additional Information:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```