#### Parser Content
```Java
{
Name = vmware-view-login
  Vendor = VMware View
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ View - """, """_USERLOGGEDIN""", """Severity="AUDIT_SUCCESS"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+\d+\s+""",
    """({app}View)""",
    """\s+({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """\s+ForwardedClientIpAddress="[^"]*?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\s+({dest_host}[^\s]+)\s+View - """,
    """UserDisplayName="(({domain}[^\\]+)\\+)?({user}[^"]+)"""",
   ]
}
```