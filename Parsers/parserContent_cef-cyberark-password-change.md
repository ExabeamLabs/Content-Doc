#### Parser Content
```Java
{
Name = cef-cyberark-password-change
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Splunk
  DataType = "password-change"
  TimeFormat = "epoch"
  Conditions = [  """|Cyber-Ark|Vault|""", """|Set Password|""", """Safe""" ]
  Fields = [
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) CEF""",
    """\srt=({time}\d+)(\s+\w+=|\s*$)""",
    """\sdvc=({host}\S+)(\s+\w+=|\s*$)""",
    """\sdvchost=({host}\S+)(\s+\w+=|\s*$)""",
    """\ssrc=({src_ip}\S+)(\s+\w+=|\s*$)""",
    """\sshost="?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]+))"?(\s+\w+=|\s*$)""",
    """\ssuser=(({domain}[^\\=]+)(\\)+)?({user}.+?)(\s+\w+=|\s*$)""",
    """act=Set Password\s+duser=(({domain}[^\\=]+)(\\)+)?({user}.+?)\s+\w+=""",
    """({app}Cyber-Ark)""",
  ]
}
```