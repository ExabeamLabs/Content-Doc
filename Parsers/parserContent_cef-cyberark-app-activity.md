#### Parser Content
```Java
{
Name = cef-cyberark-app-activity
  Vendor = CyberArk Vault
  Product = CyberArk Vault
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [  """CEF""", """|Cyber-Ark|Vault|""", """Safe""" ]
  Fields = [
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) CEF""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\srt=({time}\d+)(\s+\w+=|\s*$)""",
    """\sdvc="?({host}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\sdvchost="?({host}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\ssrc="?({src_ip}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """shost="?(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]+))"?(\s+\w+=|\s*$)""",
    """\sfname="?({domain}[^"\\]+)\\+[^"]+"""",
    """\Wduser="?(|(({domain}[^\\="]+)(\\)+)?({user}[^"]+?))"?\s+(\w+=|$)""",
    """\ssuser="?(|(({domain}[^\\="]+)(\\)+)?({user}[^"]+?))"?(\s+\w+=|\s*$)""",
    """\sfname="?(|({file_path}({file_parent}[^="]*?[\\\/]+)?({file_name}[^="\\\/]+?(\.({file_ext}\w+))?)))"?(\s+\w+=|\s*$)""",
    """({file_type}(?i)file)""",
    """({app}Cyber-Ark)"""
    """\Wact="?({activity}[^"=\[\]]+?)"?(\[|\]|\s+\w+=|\s*$)"""
  ]
  DupFields=[ "file_name->object", "file_path->additional_info", "activity->accesses" ]
}
```