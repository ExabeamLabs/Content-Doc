#### Parser Content
```Java
{
Name = vmware-view-app-activity
  Vendor = VMware View
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ View - """, """Severity="""", """DesktopId="""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+\d+\s+""",
    """\s+({dest_host}[^\s]+)\s+View - """,
    """\s+({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """UserDisplayName="(({domain}[^\\]+)\\+)?\\*({user}[^"\\]+)"""",
    """MachineName="({dest_host}[^"]+)"""",
    """EventType="({activity}[^"]+)"""",
    """DesktopId="({object}[^"]+)"""",
    """_USER_.+?UserDisplayName="([^\\]+\\+)?({object}[^"]+)"""",
    """\] ({additional_info}.+?)\s*$""",
    """Severity="({alert_severity}[^"]+)"""",
  ]
}
```