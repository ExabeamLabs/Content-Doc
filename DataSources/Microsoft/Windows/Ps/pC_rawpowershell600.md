#### Parser Content
```Java
{
Name = raw-powershell-600
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """relay=""", """Event_ID="600"""", """Windows PowerShell""" ]
  Fields = [
    """SystemTime="({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z)"""",
    """Computer="({host}[^"]{1,2000})"""",
    """({process_name}PowerShell)""",
    """Event_ID="({event_code}\d{1,100})"""",
    """HostApplication=({command_line}[^\n]{1,2000}?)\s{1,100}EngineVersion=""",
    """sourceip="({src_ip}[a-fA-F\d:.]{1,2000})"""
  ]


}
```