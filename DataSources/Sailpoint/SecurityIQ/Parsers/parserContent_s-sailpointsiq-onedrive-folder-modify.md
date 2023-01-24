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
s-sailpointsiqonedrive-activity = {
  Vendor = Sailpoint
  Product = SecurityIQ
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """creation_timestamp\s:\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
    """ipaddress\s:\s({host}[^|]+)\s\|""",
    """applicationtype\s:\s({app}[^|]+)\s\|""",
    """fileextension\s:\s({file_ext}[^|]+)\s\|""",
    """userfullname\s:\s({user_email}[^|]+)\s\|""",
    """objectname\s:\s({file_name}[^|]+) \|""",
    """\spath\s:\s({file_parent}[^|]+)\s\|"""
  ]

```