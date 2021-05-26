#### Parser Content
```Java
{
Name = cef-cyberark-app-activity
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [  """CEF""", """|Cyber-Ark|Vault|""", """Safe""" ]
  Fields = [
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) CEF""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\srt=({time}\d{1,100})(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvc="?({host}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost="?({host}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc="?({src_ip}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """shost="?(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]{1,2000}))"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfname="?({domain}[^"\\]{1,2000})\\+[^"]{1,2000}"""",
    """\Wduser="?(|(({domain}[^\\="]{1,2000})(\\)+)?({user}[^"]{1,2000}?))"?\s{1,100}(\w+=|$)""",
    """\ssuser="?(|(({domain}[^\\="]{1,2000})(\\)+)?({user}[^"]{1,2000}?))"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfname="?(|({file_path}({file_parent}[^="]{0,2000}?[\\\/]{1,2000})?({file_name}[^="\\\/]{1,2000}?(\.({file_ext}\w+))?)))"?(\s{1,100}\w+=|\s{0,100}$)""",
    """({file_type}(?i)file)""",
    """({app}Cyber-Ark)"""
    """\Wact="?({activity}[^"=\[\]]{1,2000}?)"?(\[|\]|\s{1,100}\w+=|\s{0,100}$)"""
  ]
  DupFields=[ "file_name->object", "file_path->additional_info", "activity->accesses" ]
}
```