#### Parser Content
```Java
{
Name = s-sailpointsiq-sponline-file-operations
  Vendor = Sailpoint
  Product = SecurityIQ
  Lms = Splunk
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = ["""| applicationtype : SharePoint Online |""", """actiontype : File """]
  Fields = [
    """creation_timestamp\s:\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
    """ipaddress\s:\s({host}[^|]{1,2000})\s\|""",
    """applicationtype\s:\s({app}[^|]{1,2000})\s\|""",
    """fileextension\s:\s({file_ext}[^|]{1,2000})\s\|""",
    """domain\s:\s({domain}[^|]{1,2000})\s\|""",
    """\spath\s:\s({file_parent}[^|]{1,2000})\s\|"""
    """userfullname\s:\s({user_email}[^|]{1,2000})\s\|""",
    """objectname\s:\s({file_name}[^|]{1,2000}) \|""",
    """actiontype\s:\sFile\s({activity}[^\s]{1,2000})(\s|\sExtended\s)\|"""
  ]
  DupFields = [ "host->dest_ip", "activity->accesses" ]
}
```