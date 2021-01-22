#### Parser Content
```Java
{
Name = cef-cyberark-account-switch-1
  Vendor = CyberArk Vault
  Product = CyberArk Vault
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """|Cyber-Ark|Vault|""", """|Retrieve password|""", """Safe""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(z|Z)?""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) CEF:""",
    """\d\d:\d\d:\d\d ({dest_host}[\w\-.]+) CEF:""",
    """\sdvc="?({host}[^"\s]+?)"?(\s+\w+=|\s*$)""",
    """\sdvchost="?({host}[^"\s]+?)"?(\s+\w+=|\s*$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost="?(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]+))"?(\s+\w+=|\s*$)""",
    """\sfname="?({domain}[^"\\]+)\\+[^"]+"""",
    """\ssuser="?(({domain}[^\\="]+?)(\\)+)?({user}[^"]+?)"?\s+\w+=""",
    """\sfname=[^=]+?\-({account}[^\s-]+?)\s+\w+=""",
    """\sdhost="?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))""",
    """\sduser="?([^\\="]+\\+)?({account}[^="]+?)"?\s+\w+=""",
    """cs2="?({safe_value}[^"]+?)"?\s+\w+="""
  ]
}
```