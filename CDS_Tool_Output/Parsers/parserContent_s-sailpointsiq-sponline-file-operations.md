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
    """ipaddress\s:\s({host}[^|]+)\s\|""",
    """applicationtype\s:\s({app}[^|]+)\s\|""",
    """fileextension\s:\s({file_ext}[^|]+)\s\|""",
    """domain\s:\s({domain}[^|]+)\s\|""",
    """\spath\s:\s({file_parent}[^|]+)\s\|"""
    """userfullname\s:\s({user_email}[^|]+)\s\|""",
    """objectname\s:\s({file_name}[^|]+) \|""",
    """actiontype\s:\sFile\s({activity}[^\s]+)(\s|\sExtended\s)\|"""
  ]
  DupFields = [ "host->dest_ip", "activity->accesses" ]
}
```