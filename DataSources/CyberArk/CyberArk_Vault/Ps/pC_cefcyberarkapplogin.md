#### Parser Content
```Java
{
Name = cef-cyberark-app-login
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [  """|Cyber-Ark|Vault|""", """|Logon|""", """Safe""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(z|Z)?""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\srt=({time}\d{1,100})(\s{1,100}\w+=|\s{0,100}$)""",
    """\d\d:\d\d:\d\d(z|Z)? ({host}[\w\-.]{1,2000}) CEF:""",
    """\d\d:\d\d:\d\d(z|Z)? ({dest_host}[\w\-.]{1,2000}) CEF:""",
    """\sdvc="?({host}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost="?({host}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc="?({src_ip}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sshost="?(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]{1,2000}))"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfname="?({domain}[^"\\]{1,2000})\\+[^"]{1,2000}"""",
    """\ssuser="?(({domain}[^\\="]{1,2000})(\\)+)?({user}[^"]{1,2000}?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """act=Logon\s{1,100}duser=(({domain}[^\\=]{1,2000})(\\)+)?({user}.+?)\s{1,100}\w+=""",
    """({app}Cyber-Ark)"""
  ]
}
```