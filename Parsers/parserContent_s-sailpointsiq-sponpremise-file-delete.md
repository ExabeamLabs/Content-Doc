#### Parser Content
```Java
{
Name = s-sailpointsiq-sponpremise-file-delete
  Vendor = Sailpoint
  Lms = Splunk
  Product = SecurityIQ
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = ["""| applicationtype : Sharepoint |""", """actiontype : Delete"""]
  
  Fields = [
    """creation_timestamp\s:\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
    """ipaddress\s:\s({host}[^|]+)\s\|""",
    """userfullname\s:\s({user_sid}(?=[^\\]+\\)({domain}[^\\]+)\\({user}.+?)|(?:.+?))\s\|""",
    """objectname\s:\s({file_name}[^|]+)\s\|""",
    """domain\s:\s({domain}[^|]+)\s\|""",
    """applicationtype\s:\s({app}[^|]+)\s\|""",
    """\spath\s:\s({file_parent}[^|]+)\s\|""",
    """fileextension\s:\s({file_ext}[^|]+)\s\|""",
    """actiontype\s:\s({activity}[^\ ]+)(\s|\s\([^\)]+\)\s)\|"""
  ]
  DupFields = [ "host->dest_ip", "activity->accesses" ]
}
```