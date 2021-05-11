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
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s{1,100}\d{1,100}\s{1,100}""",
    """({app}View)""",
    """\s{1,100}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """\sUserSID="({user_sid}[^"]+)"""",
    """UserDisplayName="(({domain}[^\\]+)\\+)?({user}[^"]+)"""",
    """MachineName="({dest_host}[^"]+)"""",
   ]
}
```