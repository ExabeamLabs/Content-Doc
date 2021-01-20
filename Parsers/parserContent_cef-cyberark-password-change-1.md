#### Parser Content
```Java
{
Name = cef-cyberark-password-change-1
  Vendor = CyberArk Vault
  Product = CyberArk Vault
  Lms = Splunk
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """|Cyber-Ark|Vault|""", """|CPM Change Password|""", """Safe""" ]
  Fields = [
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) CEF""",
    """\srt=({time}\d+)(\s+\w+=|\s*$)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sdvc="?({host}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\sdvchost="?({host}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\ssrc="?({src_ip}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\sshost="?({src_host}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\sfname="?({domain}[^"\\]+)\\+[^"]+"""",
    """\ssuser="?(({domain}[^\\="]+)(\\)+)?({user}[^"]+?)"?(\s+\w+=|\s*$)""",
    """\sduser="?(({domain}[^\\="]+)(\\)+)?({user}[^"]+?)"?\s+\w+=""",
    """({app}Cyber-Ark)""",
  ]
}
```