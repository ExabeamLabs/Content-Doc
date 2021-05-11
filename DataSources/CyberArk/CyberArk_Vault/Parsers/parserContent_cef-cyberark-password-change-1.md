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
    """\srt=({time}\d{1,100})(\s{1,100}\w+=|\s{0,100}$)""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s\w+\s{1,100}CEF:""",
    """\sdvc="?({host}[^"\s]+)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost="?({host}[^"\s]+)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc="?({src_ip}[^"\s]+)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sshost="?(?:({src_ip}[A-Fa-f:\d.]+)|({src_host}[^"\s\=]+))"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfname="?({domain}[^"\\]+)\\+[^"]+"""",
    """\ssuser="?(({domain}[^\\="]+)(\\)+)?({user}[^"]+?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sduser="?(({domain}[^\\="]+)(\\)+)?({user}[^"]+?)"?\s{1,100}\w+=""",
    """({app}Cyber-Ark)"""
  ]
}
```