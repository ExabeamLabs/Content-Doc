#### Parser Content
```Java
{
Name = s-sailpointsiq-netappcifs-folder-delete
  DataType = "file-operations"
  Conditions = ["""| applicationtype : Netapp - CIFS |""", """actiontype : Delete Folder"""]
  
  Fields = ${SailPointSIQNetAppCIFSTemplates.s-sailpointsiqnetappcifs-activity.Fields} [
    """objectname\s:\s({file_name}[^|]{1,2000})\s\|""",
    """\spath\s:\s({file_parent}[^|]{1,2000})\s\|""",
	"""subjecttype\s:\s({file_type}[^|]{1,2000})\s""",
    """actiontype\s:\s({event_name}[^|]{1,2000})\sFolder\s\|"""
  ]
  DupFields = [ "host->dest_ip", "event_name->accesses" ]
}
s-sailpointsiqnetappcifs-activity = {
  Vendor = Sailpoint
  Product = SecurityIQ
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """creation_timestamp\s:\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
    """ipaddress\s:\s({host}[^|]{1,2000}) \|""",
    """applicationtype\s:\s({app}[^|]{1,2000})\s\|""",
    """fileextension\s:\s({file_ext}[^|]{1,2000})\s\|""",
    """userfullname\s:\s({user_sid}(?=[^\\]{1,2000}\\)({domain}[^\\]{1,2000})\\({user}.+?)|(?:.+?))\s\|"""
  ]

```