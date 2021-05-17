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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\S+\s{1,100}({user}[^\s]{1,2000})\s{1,100}\S+\s{1,100}({src_ip}[A-Fa-f:\d.]{1,2000})\s{1,100}""",
    """start_time=({time}\d{1,100})""",
    """cmd=\S+\s{1,100}({command_line}.+?)\s{1,100}$""",
    """cmd=\S+\s{1,100}({process_name}[^\s]{1,2000})"""
  ]
}
```