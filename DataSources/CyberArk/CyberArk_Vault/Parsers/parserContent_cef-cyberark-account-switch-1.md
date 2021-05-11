#### Parser Content
```Java
{
Name = cef-cyberark-account-switch-1
  Vendor = CyberArk
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
    """\sdvc="?({host}[^"\s]+?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost="?({host}[^"\s]+?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost="?(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]+))"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfname="?({domain}[^"\\]+)\\+[^"]+"""",
    """\ssuser="?(({domain}[^\\="]+?)(\\)+)?({user}[^"]+?)"?\s{1,100}\w+=""",
    """\sfname=[^=]+?\-({account}[^\s-]+?)\s{1,100}\w+=""",
    """\sdhost="?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))""",
    """\sduser="?([^\\="]+\\+)?({account}[^="]+?)"?\s{1,100}\w+=""",
    """cs2="?({safe_value}[^"]+?)"?\s{1,100}\w+="""
  ]
}
```