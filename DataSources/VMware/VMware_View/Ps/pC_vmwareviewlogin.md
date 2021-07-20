#### Parser Content
```Java
{
Name = vmware-view-login
  Vendor = VMware
  Product = VMware View
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ View - """, """_USERLOGGEDIN""", """Severity="AUDIT_SUCCESS"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}\d{1,100}\s{1,100}""",
    """({app}View)""",
    """\s{1,100}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """\s{1,100}ForwardedClientIpAddress="[^"]{0,2000}?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\s{1,100}({dest_host}[^\s]{1,2000})\s{1,100}View - """,
    """UserDisplayName="(({domain}[^\\]{1,2000})\\+)?({user}[^"]{1,2000})"""",
   ]
}
```