#### Parser Content
```Java
{
Name = tacacs-process-created
  Vendor = Cisco
  Product = Cisco TACACS
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """[TACACS]""", """start_time=""", """cmd=""" ]
  Fields = [
    """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({host}[\w\-.]+)\s+\S+\s+({user}[^\s]+)\s+\S+\s+({src_ip}[A-Fa-f:\d.]+)\s+""",
    """start_time=({time}\d+)""",
    """cmd=\S+\s+({command_line}.+?)\s+$""",
    """cmd=\S+\s+({process_name}[^\s]+)"""
  ]
}
```