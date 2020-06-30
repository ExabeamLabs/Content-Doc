#### Parser Content
```Java
{
Name = cef-powershell-600
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF: """, """|Microsoft|PowerShell|""", """|PowerShell:600|""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\sahost=({host}[^\s]+)\s""",
    """\sad.ProcessID=({pid}[^\s]+)\s""",
    """\sdeviceSeverity=({alert_severity}[^\s]+)\s""",
    """\srequestClientApplication=({parent_process}.+?)\scs2=""",
    """\smsg=({additional_info}.+?)\sart=""",
  ]
}
```