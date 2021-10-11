#### Parser Content
```Java
{
Name = f5-process-created
  DataType = "process-created"
  Conditions = [ """"log_type":"WAF"""", """"log_vendor":"f5"""", """ CMD """, """]: (""" ]
  Fields = ${F5ParserTemplates.f5-waf-activity.Fields} [
    """\(({user}[^\}\s]{1,2000})\) CMD""",
    """\sCMD \(\s{0,100}({command_line}[^\)]{1,2000})\)""",
    """\sCMD \(\s{0,100}[^\/]{0,2000}?({process}({directory}\/[^\)]{0,2000}?)({process_name}[^\/]{0,2000}?[^\\]))((\\\\)*\s|\))"""
  ]
  DupFields = [ "directory->process_directory" ]
}
f5-waf-activity = {
    Vendor = F5
    Product = F5 Advanced Web Application Firewall (WAF)
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S+)""",
      """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"host":"(::ffff:)?({host}[^"]{1,2000})""",
      """\d\d:\d\d:\d\d ({host}[^\s]{1,2000}) \w+ \w+\["""
    ]
 
```