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
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) CEF""",
    """\srt=({time}\d{1,100})(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvc=({host}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost=({host}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc=({src_ip}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sshost="?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]{1,2000}))"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssuser=(({domain}[^\\=]{1,2000})(\\)+)?({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """act=Set Password\s{1,100}duser=(({domain}[^\\=]{1,2000})(\\)+)?({user}.+?)\s{1,100}\w+=""",
    """({app}Cyber-Ark)""",
  ]


}
```