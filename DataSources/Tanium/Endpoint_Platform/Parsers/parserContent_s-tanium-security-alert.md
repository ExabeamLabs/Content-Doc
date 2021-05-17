#### Parser Content
```Java
{
Name = s-tanium-security-alert
    Vendor = Tanium
    Product = Endpoint Platform
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """ Tanium """, """Timestamp=""", """Computer-Name=""", """Computer-IP""" ]
    Fields = [
      """\d\d:\d\d:\d\d\.\d{1,100}(?:\+|-)\d\d:\d\d\s{1,100}({host}[\w\-\.]{1,2000})\s{1,100}Tanium""",
      """\WTimestamp="?({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)""",
      """\WEvent-Name="?({alert_name}[^"]{1,2000}?)"?\s{1,100}([\w\-]{1,2000}=|$)""",
      """\WIntel-Name="?({alert_name}[^"]{1,2000}?)"?\s{1,100}([\w\-]{1,2000}=|$)""",
      """\WDetect="?({alert_type}[^"]{1,2000}?)"?\s{1,100}([\w\-]{1,2000}=|$)""",
      """\WIntel-Type="?({alert_type}[^"]{1,2000}?)"?\s{1,100}([\w\-]{1,2000}=|$)""",
      """\WPriority="?({alert_severity}[^\s"]{1,2000}?)"?\s{1,100}([\w\-]{1,2000}=|$)""",
      """\WEvent-Id="?({alert_id}[\w\-]{1,2000})""",
      """\WAlert-Id="?({alert_id}[\w\-]{1,2000})""",
      """\WComputer-Name="?({src_host}[\w\-.]{1,2000})"?\s{1,100}([\w\-]{1,2000}=|$)""",
      """\WComputer-IP="?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sMatch-Details=({additional_info}.+?)(\s{0,100}$|(\s\w+=))""",
      """\sMatch-Details="?\[?({additional_info}[^\]]{1,2000}?)\]"\](\s{0,100}$|(\s\w+=))""",
      """\sMatch-Details.*"{1,20}user"{1,20}:"{1,20}(({domain}[^\\"]{1,2000})\\+)?({user}[^",]{1,2000})(?!.*user)"{1,20}""", 
      """\sMatch-Details.*"{1,20}properties"{1,20}:\{"{1,20}args"{1,20}:.*?\{"{1,20}fullpath"{1,20}:"{1,20}({path}(({directory}[^"]{1,2000})[\\/])?({process_name}[^"]{1,2000}?))"{1,20}""",
      """Match-Details.*"{1,20}properties"{1,20}:\{"{1,20}args"{1,20}:"({command_line}.*?)","{1,20}cwd"""
    ]
  }
```