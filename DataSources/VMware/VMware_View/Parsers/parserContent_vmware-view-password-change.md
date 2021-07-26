#### Parser Content
```Java
{
Name = vmware-view-password-change
  Vendor = VMware
  Product = VMware View
  Lms = Splunk
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ View - """, """BROKER_USERCHANGEDPASSWORD""", """Severity="AUDIT_SUCCESS"""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}\d{1,100}\s{1,100}""",
    """\s{1,100}({dest_host}[^\s]{1,2000})\s{1,100}View - """,
    """\s{1,100}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """UserDisplayName="(({domain}[^\\]{1,2000})\\+)?({user}[^"]{1,2000})"""",
   ]
}
```