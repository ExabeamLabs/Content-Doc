#### Parser Content
```Java
{
Name = raw-4700
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-task-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """4700""", """A scheduled task was enabled""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+?)</Computer>""",
    """({event_code}4700)""",
    """({event_name}A scheduled task was enabled)""",
    """\sAccount Name:\s{0,100}(|({user}[^:]+?))\s{0,100}Account Domain:\s{0,100}(|({domain}[^:]+?))\s{0,100}Logon ID:\s{0,100}(|({logon_id}[^:]+?))\s{0,100}Task Information:""",
    """Task Name:\s{0,100}({task_name}[^:]+?)\s{0,100}Task Content:""",
    """Task Content:\s{0,100}({additional_info}[^<]+?)\s{0,100}<"""
  ]
}
```