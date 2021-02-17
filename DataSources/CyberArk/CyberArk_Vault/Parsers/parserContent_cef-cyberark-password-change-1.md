#### Parser Content
```Java
{
Name = cef-cyberark-password-change-1
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Splunk
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [  """|Cyber-Ark|Vault|""", """|CPM Change Password|""", """Safe""" ]
  Fields = [
    """\d\d:\d\d:\d\dZ? ({host}[\w\-.]+) CEF""",
    """\srt=({time}\d+)(\s+\w+=|\s*$)""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s\w+\s+CEF:""",
    """\sdvc="?({host}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\sdvchost="?({host}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\ssrc="?({src_ip}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\sshost="?(?:({src_ip}[A-Fa-f:\d.]+)|({src_host}[^"\s\=]+))"?(\s+\w+=|\s*$)""",
    """\sfname="?({domain}[^"\\]+)\\+[^"]+"""",
    """\ssuser="?(({domain}[^\\="]+)(\\)+)?({user}[^"]+?)"?(\s+\w+=|\s*$)""",
    """\sduser="?(({domain}[^\\="]+)(\\)+)?({user}[^"]+?)"?\s+\w+=""",
    """({app}Cyber-Ark)"""
  ]
}
```