#### Parser Content
```Java
{
Name = vmware-remote-logon-1
  Vendor = VMware
  Product = VMware Horizon
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """View The agent running on machine""", """has accepted an allocated session""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+[\+\-]\d\d:\d\d)\s+({host}[\w\-.]+)\s+View The agent running on machine\s+({dest_host}[\w\-.]+)\s+has accepted an allocated session for user (({domain}[^\\\s]+)\\+)?({user}[^\\\s]+)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+View""",
    """The agent running on machine\s+({dest_host}[\w\-.]+)\s+has accepted an allocated session""",
    """for user (?:({domain}[^\\\s]+)\\+)?({user}[^\\\s]+)""",
   ]
}
```