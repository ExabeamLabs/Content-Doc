#### Parser Content
```Java
{
Name = s-sailpointsiq-onedrive-file-write
  DataType = "file-operations"
  Conditions = ["""| applicationtype : OneDrive """, """actiontype : File Modified"""]
  
  Fields = ${SailPointSIQOneDriveTemplates.s-sailpointsiqonedrive-activity.Fields} [
    """actiontype\s:\sFile\s({activity}[^\s]+)(\s|\sExtended\s)\|"""
  ]
  DupFields = [ "host->dest_ip" ]
}
```