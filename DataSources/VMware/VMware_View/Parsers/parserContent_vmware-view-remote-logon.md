#### Parser Content
```Java
{
Name = vmware-view-remote-logon
  Vendor = VMware
  Product = VMware View
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ View - """, """AGENT_CONNECTED""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}\d{1,100}\s{1,100}""",
    """({app}View)""",
    """\s{1,100}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """\sUserSID="({user_sid}[^"]{1,2000})"""",
    """UserDisplayName="(({domain}[^\\]{1,2000})\\+)?({user}[^"]{1,2000})"""",
    """MachineName="({dest_host}[^"]{1,2000})"""",
   ]
}
```