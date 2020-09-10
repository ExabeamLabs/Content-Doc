#### Parser Content
```Java
{
Name = vmware-view-remote-logon
  Vendor = VMware View
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ View - """, """AGENT_CONNECTED""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+\d+\s+""",
    """\s+({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """\sUserSID="({user_sid}[^"]+)"""",
    """UserDisplayName="(({domain}[^\\]+)\\+)?({user}[^"]+)"""",
    """MachineName="({dest_host}[^"]+)"""",
   ]
}
```