#### Parser Content
```Java
{
Name = vmware-view-app-activity
  Vendor = VMware
  Product = VMware View
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ View - """, """Severity="""", """DesktopId="""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s{1,100}\d{1,100}\s{1,100}""",
    """({app}View)""",
    """\s{1,100}({dest_host}[^\s]+)\s{1,100}View - """,
    """\s{1,100}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """UserDisplayName="(({domain}[^\\]+)\\+)?\\*({user}[^"\\]+)"""",
    """MachineName="({dest_host}[^"]+)"""",
    """EventType="({activity}[^"]+)"""",
    """DesktopId="({object}[^"]+)"""",
    """_USER_.+?UserDisplayName="([^\\]+\\+)?({object}[^"]+)"""",
    """\] ({additional_info}.+?)\s{0,100}$""",
    """Severity="({alert_severity}[^"]+)"""",
  ]
}
```