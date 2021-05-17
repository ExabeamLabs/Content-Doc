#### Parser Content
```Java
{
Name = vmware-view-failed-login
  Vendor = VMware
  Product = VMware View
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ View - """, """_USER_AUTHFAILED""", """Severity="AUDIT_FAIL"""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}\d{1,100}\s{1,100}""",
    """\s{1,100}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """({app}View)""",
    """\s{1,100}({dest_host}[^\s]{1,2000})\s{1,100}View - """,
    """\s{1,100}ClientIpAddress="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """UserDisplayName="(({domain}[^\\]{1,2000})\\+)?({user}[^"]{1,2000})"""",
    """USER_AUTHFAILED_({failure_reason}[^"]{1,2000})""""
   ]
}
```