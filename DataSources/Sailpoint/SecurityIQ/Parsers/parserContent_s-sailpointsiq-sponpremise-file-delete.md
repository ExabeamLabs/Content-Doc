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
    """ipaddress\s:\s({host}[^|]{1,2000})\s\|""",
    """userfullname\s:\s({user_sid}(?=[^\\]{1,2000}\\)({domain}[^\\]{1,2000})\\({user}.+?)|(?:.+?))\s\|""",
    """objectname\s:\s({file_name}[^|]{1,2000})\s\|""",
    """domain\s:\s({domain}[^|]{1,2000})\s\|""",
    """applicationtype\s:\s({app}[^|]{1,2000})\s\|""",
    """\spath\s:\s({file_parent}[^|]{1,2000})\s\|""",
    """fileextension\s:\s({file_ext}[^|]{1,2000})\s\|""",
    """actiontype\s:\s({activity}[^\ ]{1,2000})(\s|\s\([^\)]{1,2000}\)\s)\|"""
  ]
  DupFields = [ "host->dest_ip", "activity->accesses" ]
}
```