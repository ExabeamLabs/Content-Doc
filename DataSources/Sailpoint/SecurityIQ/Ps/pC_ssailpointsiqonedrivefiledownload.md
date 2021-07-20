#### Parser Content
```Java
{
Name = s-sailpointsiq-onedrive-file-download
  DataType = "file-operations"
  Conditions = ["""| applicationtype : OneDrive """, """actiontype : File Downloaded"""]
  
  Fields = ${SailPointSIQOneDriveTemplates.s-sailpointsiqonedrive-activity.Fields} [
    """actiontype\s:\sFile\s({activity}[^|]{1,2000})\s\|"""
  ]
  DupFields = [ "host->dest_ip" ]
}
s-sailpointsiqonedrive-activity = {
  Vendor = Sailpoint
  Product = SecurityIQ
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """creation_timestamp\s:\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
    """ipaddress\s:\s({host}[^|]{1,2000})\s\|""",
    """applicationtype\s:\s({app}[^|]{1,2000})\s\|""",
    """fileextension\s:\s({file_ext}[^|]{1,2000})\s\|""",
    """userfullname\s:\s({user_email}[^|]{1,2000})\s\|""",
    """objectname\s:\s({file_name}[^|]{1,2000}) \|""",
    """\spath\s:\s({file_parent}[^|]{1,2000})\s\|"""
  ]

```