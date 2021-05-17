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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}[\+\-]\d\d:\d\d)\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}View The agent running on machine\s{1,100}({dest_host}[\w\-.]{1,2000})\s{1,100}has accepted an allocated session for user (({domain}[^\\\s]{1,2000})\\+)?({user}[^\\\s]{1,2000})""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}View""",
    """The agent running on machine\s{1,100}({dest_host}[\w\-.]{1,2000})\s{1,100}has accepted an allocated session""",
    """for user (?:({domain}[^\\\s]{1,2000})\\+)?({user}[^\\\s]{1,2000})""",
   ]
}
```