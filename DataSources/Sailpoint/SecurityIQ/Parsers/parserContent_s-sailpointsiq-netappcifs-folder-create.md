#### Parser Content
```Java
{
Name = s-sailpointsiq-netappcifs-folder-create
  DataType = "file-operations"
  Conditions = ["""| applicationtype : Netapp - CIFS |""", """actiontype : Create Folder"""]
  
  Fields = ${SailPointSIQNetAppCIFSTemplates.s-sailpointsiqnetappcifs-activity.Fields} [
    """objectname\s:\s({file_name}[^|]+)\s\|""",
    """\spath\s:\s({file_parent}[^|]+)\s\|""",
	"""subjecttype\s:\s({file_type}[^|]+)\s""",
    """actiontype\s:\s({event_name}[^|]+)\sFolder\s\|"""
  ]
  DupFields = [ "host->dest_ip" ]
}
s-sailpointsiqnetappcifs-activity = {
  Vendor = Sailpoint
  Product = SecurityIQ
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """creation_timestamp\s:\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
    """ipaddress\s:\s({host}[^|]+) \|""",
    """applicationtype\s:\s({app}[^|]+)\s\|""",
    """fileextension\s:\s({file_ext}[^|]+)\s\|""",
    """userfullname\s:\s({user_sid}(?=[^\\]+\\)({domain}[^\\]+)\\({user}.+?)|(?:.+?))\s\|"""
  ]

```