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
    """\d\d:\d\d:\d\dZ? ({host}[\w\-.]{1,2000}) CEF""",
    """\srt=({time}\d{1,100})(\s{1,100}\w+=|\s{0,100}$)""",
    """msg=({time}\w{1,100}\s{1,100}\d\d\s{1,100}\d\d:\d\d:\d\d)[^:]{1,100}CEF:""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s\w+\s{1,100}CEF:""",
    """\sdvc="?({host}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost="?({host}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc="?({src_ip}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sshost="?(?:({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[^"\s\=]{1,2000}))"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfname="?({domain}[^"\\]{1,2000})\\+[^"]{1,2000}"""",
    """\ssuser="?(({domain}[^\\="]{1,2000})(\\)+)?({user}[^"]{1,2000}?)"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sduser="?(({domain}[^\\="]{1,2000})(\\)+)?(|({user}[^"]{1,2000}?))"?\s{1,100}\w+=""",
    """({app}Cyber-Ark)"""
  ]


}
```