#### Parser Content
```Java
{
Name = s-sailpointsiq-windowsfs-perm-remove-folder
  DataType = "file-operations"
  Conditions = ["""| applicationtype : Windows File Server (Agent) |""", """actiontype : Permission Remove Folder"""]
  
  Fields = ${SailPointSIQWindowsFSTemplates.s-sailpointsiqwindowsfs-activity.Fields} [
    """objectname\s:\s({file_name}[^|]+)\s\|""",
    """actiontype\s:\sPermission\s({accesses}[^|]+)\sFolder\s\|""",
    """\spath\s:\s({file_parent}[^|]+)\s\|""",
    """subjecttype\s:\s({file_type}[^|]+)\s\|"""
  ]
}
s-sailpointsiqwindowsfs-activity = {
  Vendor = Sailpoint
  Product = SecurityIQ
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """creation_timestamp\s:\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
    """servername\s:\s({host}[^|]+)\s\|""",
    """applicationtype\s:\s({app}[^|]+)\s\|""",
    """fileextension\s:\s({file_ext}[^|]+)\s\|""",
    """userfullname\s:\s({user_sid}(?=[^\\]+\\)({domain}[^\\]+)\\({user}.+?)|(?:.+?))\s\|""",
    """membername\s:\s({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+)\\({sid_user}\S+)|(?:.+?))\s$""",
    """actiontype\s:\s({event_name}[^|]+)\s\|"""
  ]

```