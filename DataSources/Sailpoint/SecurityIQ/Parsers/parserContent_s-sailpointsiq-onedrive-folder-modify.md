#### Parser Content
```Java
{
Name = s-sailpointsiq-onedrive-folder-modify
  DataType = "file-operations"
  Conditions = ["""| applicationtype : OneDrive """, """actiontype : Folder Modified"""]
  
  Fields = ${SailPointSIQOneDriveTemplates.s-sailpointsiqonedrive-activity.Fields} [
    """actiontype\s:\sFolder\s({activity}[^|]+)\s\|""",
    """itemtype\s:\s({file_type}[^|]+)\s\|"""
  ]
  DupFields = [ "host->dest_ip", "activity->accesses" ]
}
```