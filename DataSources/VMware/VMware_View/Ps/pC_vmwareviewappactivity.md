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
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}\d{1,100}\s{1,100}""",
    """({app}View)""",
    """\s{1,100}({dest_host}[^\s]{1,2000})\s{1,100}View - """,
    """\s{1,100}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """UserDisplayName="(({domain}[^\\]{1,2000})\\+)?\\*({user}[^"\\]{1,2000})"""",
    """MachineName="({dest_host}[^"]{1,2000})"""",
    """EventType="({activity}[^"]{1,2000})"""",
    """DesktopId="({object}[^"]{1,2000})"""",
    """_USER_.+?UserDisplayName="([^\\]{1,2000}\\+)?({object}[^"]{1,2000})"""",
    """\] ({additional_info}.+?)\s{0,100}$""",
    """Severity="({alert_severity}[^"]{1,2000})"""",
  ]
}
```