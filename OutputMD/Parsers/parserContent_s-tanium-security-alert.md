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
      """\d\d:\d\d:\d\d\.\d+(?:\+|-)\d\d:\d\d\s+({host}[\w\-\.]+)\s+Tanium""",
      """\WTimestamp="?({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)""",
      """\WEvent-Name="?({alert_name}[^"]+?)"?\s+([\w\-]+=|$)""",
      """\WIntel-Name="?({alert_name}[^"]+?)"?\s+([\w\-]+=|$)""",
      """\WDetect="?({alert_type}[^"]+?)"?\s+([\w\-]+=|$)""",
      """\WIntel-Type="?({alert_type}[^"]+?)"?\s+([\w\-]+=|$)""",
      """\WPriority="?({alert_severity}[^\s"]+?)"?\s+([\w\-]+=|$)""",
      """\WEvent-Id="?({alert_id}[\w\-]+)""",
      """\WAlert-Id="?({alert_id}[\w\-]+)""",
      """\WComputer-Name="?({src_host}[\w\-.]+)"?\s+([\w\-]+=|$)""",
      """\WComputer-IP="?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sMatch-Details=({additional_info}.+?)(\s*$|(\s\w+=))""",
      """\sMatch-Details="?\[?({additional_info}[^\]]+?)\]"\](\s*$|(\s\w+=))""",
      """\sMatch-Details.*"+user"+:"+(({domain}[^\\"]+)\\+)?({user}[^",]+)(?!.*user)"+""", 
      """\sMatch-Details.*"+properties"+:\{"+args"+:.*?\{"+fullpath"+:"+({path}(({directory}[^"]+)[\\/])?({process_name}[^"]+?))"+""",
      """Match-Details.*"+properties"+:\{"+args"+:"({command_line}.*?)","+cwd"""
    ]
  }
```