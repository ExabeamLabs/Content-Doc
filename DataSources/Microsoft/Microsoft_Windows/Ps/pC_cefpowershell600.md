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
    """\sahost=({host}[^\s]{1,2000})\s""",
    """\sad.ProcessID=({pid}[^\s]{1,2000})\s""",
    """\sdeviceSeverity=({alert_severity}[^\s]{1,2000})\s""",
    """\srequestClientApplication=({parent_process}.+?)\scs2=""",
    """\smsg=({additional_info}.+?)\sart=""",
  ]


}
```