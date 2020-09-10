#### Parser Content
```Java
{
Name = vmware-view-failed-login
  Vendor = VMware View
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ View - """, """_USER_AUTHFAILED""", """Severity="AUDIT_FAIL"""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+\d+\s+""",
    """\s+({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """\s+({dest_host}[^\s]+)\s+View - """,
    """\s+ClientIpAddress="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """UserDisplayName="(({domain}[^\\]+)\\+)?({user}[^"]+)"""",
    """USER_AUTHFAILED_({failure_reason}[^"]+)""""
   ]
}
```