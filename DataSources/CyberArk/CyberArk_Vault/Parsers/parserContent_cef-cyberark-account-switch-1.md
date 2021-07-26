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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(z|Z)?""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) CEF:""",
    """\d\d:\d\d:\d\d ({dest_host}[\w\-.]{1,2000}) CEF:""",
    """\sdvc="?({host}[^"\s]{1,2000}?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost="?({host}[^"\s]{1,2000}?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost="?(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]{1,2000}))"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfname="?({domain}[^"\\]{1,2000})\\+[^"]{1,2000}"""",
    """\ssuser="?(({domain}[^\\="]{1,2000}?)(\\)+)?({user}[^"]{1,2000}?)"?\s{1,100}\w+=""",
    """\sfname=[^=]{1,2000}?\-({account}[^\s-]{1,2000}?)\s{1,100}\w+=""",
    """\sdhost="?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]{1,2000}))""",
    """\sduser="?([^\\="]{1,2000}\\+)?({account}[^="]{1,2000}?)"?\s{1,100}\w+=""",
    """cs2="?({safe_value}[^"]{1,2000}?)"?\s{1,100}\w+="""
  ]
}
```