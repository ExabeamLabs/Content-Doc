#### Parser Content
```Java
{
Name = cef-cyberark-failed-app-login
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "epoch"
  Conditions = [  """|Cyber-Ark|Vault|""", """|Failure: User Authentication|""", """Safe""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(z|Z)?""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\srt=({time}\d+)(\s+\w+=|\s*$)""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) CEF:""",
    """\d\d:\d\d:\d\d ({dest_host}[\w\-.]+) CEF:""",
    """\sdvc="?({host}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\sdvchost="?({host}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\ssrc="?({src_ip}[^"\s]+)"?(\s+\w+=|\s*$)""",
    """\sshost="?(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]+))"?(\s+\w+=|\s*$)""",
    """\sfname="?({domain}[^"\\]+)\\+[^"]+"""",
    """\ssuser="?(({domain}[^\\="\s]+)(\\)+)?({user}[^"\\\s]+?)"?(\s+\w+=|\s*$)""",
    """\sduser="?(({domain}[^\\="\s]+)(\\)+)?({user}[^"\\\s]+?)"?\s+\w+=""",
    """({app}Cyber-Ark)"""
  ]
}
```