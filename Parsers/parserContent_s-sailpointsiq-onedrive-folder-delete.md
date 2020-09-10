#### Parser Content
```Java
{
Name = s-sailpointsiq-onedrive-folder-delete
  DataType = "file-operations"
  Conditions = ["""| applicationtype : OneDrive """, """actiontype : Folder Deleted"""]
  
  Fields = ${SailPointSIQOneDriveTemplates.s-sailpointsiqonedrive-activity.Fields} [
    """actiontype\s:\sFolder\s({activity}[^|]+)\s\|""",
    """itemtype\s:\s({file_type}[^|]+)\s\|"""
  ]
  DupFields = [ "host->dest_ip" ]
}
```