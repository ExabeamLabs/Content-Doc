#### Parser Content
```Java
{
Name = s-sailpointsiq-onedrive-file-upload
  DataType = "file-operations"
  Conditions = ["""| applicationtype : OneDrive """, """actiontype : File Uploaded"""]
  
  Fields = ${SailPointSIQOneDriveTemplates.s-sailpointsiqonedrive-activity.Fields} [
    """actiontype\s:\sFile\s({activity}[^|]+)\s\|"""
  ]
  DupFields = [ "host->dest_ip" ]
}
```