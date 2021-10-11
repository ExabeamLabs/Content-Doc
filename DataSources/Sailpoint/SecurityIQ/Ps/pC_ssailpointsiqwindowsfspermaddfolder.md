#### Parser Content
```Java
{
Name = s-sailpointsiq-windowsfs-perm-add-folder
  DataType = "file-operations"
  Conditions = ["""| applicationtype : Windows File Server (Agent) |""", """actiontype : Permission Add Folder"""]
  
  Fields = ${SailPointSIQWindowsFSTemplates.s-sailpointsiqwindowsfs-activity.Fields} [
    """objectname\s:\s({file_name}[^|]{1,2000})\s\|""",
    """actiontype\s:\sPermission\s({accesses}[^|]{1,2000})\sFolder\s\|""",
    """\spath\s:\s({file_parent}[^|]{1,2000})\s\|""",
    """subjecttype\s:\s({file_type}[^|]{1,2000})\s\|"""
  ]
}
s-sailpointsiqwindowsfs-activity = {
  Vendor = Sailpoint
  Product = SecurityIQ
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """creation_timestamp\s:\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
    """servername\s:\s({host}[^|]{1,2000})\s\|""",
    """applicationtype\s:\s({app}[^|]{1,2000})\s\|""",
    """fileextension\s:\s({file_ext}[^|]{1,2000})\s\|""",
    """userfullname\s:\s({user_sid}(?=[^\\]{1,2000}\\)({domain}[^\\]{1,2000})\\({user}.+?)|(?:.+?))\s\|""",
    """membername\s:\s({account_id}(?=[^\\]{1,2000}\\)({sid_domain}[^\\]{1,2000})\\({sid_user}\S+)|(?:.+?))\s$""",
    """actiontype\s:\s({event_name}[^|]{1,2000})\s\|"""
  ]

```