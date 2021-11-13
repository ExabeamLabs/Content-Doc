#### Parser Content
```Java
{
Name = juniper-process-created-1
  Conditions = [ """]: UI_CMDLINE_READ_LINE: User """, """, command """ ]

juniper-process-created = {
  Vendor = Juniper Networks
  Product = Juniper Networks
  Lms = Splunk
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s{1,100}\d{1,100}\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})\s""",
    """User '({user}[^']{1,2000})'""",
    """ command '({command_line}[^']{1,2000}?)\s{0,100}'""",
  
}
```