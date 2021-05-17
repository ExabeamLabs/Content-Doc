#### Parser Content
```Java
{
Name = s-sailpointsiq-windowsfs-member-removed
  DataType = "member-removed"
  Conditions = ["""| applicationtype : Windows File Server (Agent) |""", """actiontype : Member Removed"""]
  
  Fields = ${SailPointSIQWindowsFSTemplates.s-sailpointsiqwindowsfs-activity.Fields} [
        """objectname\s:\s({group_id}(?=[^\\]{1,2000}\\)({group_domain}[^\\]{1,2000})\\({group_name}.+?)|(?:.+?)) \|"""
  ]
  DupFields = [ "host->dest_host" ]
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