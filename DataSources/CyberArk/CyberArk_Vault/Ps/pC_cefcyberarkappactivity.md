#### Parser Content
```Java
{
Name = cef-cyberark-app-activity
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [  """CEF""", """|Cyber-Ark|Vault|""", """Safe""" ]
  Fields = [
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) CEF""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """\srt=({time}\d{1,100})(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvc="?({host}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost="?({host}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """dhost="?({host}[^\s"]{1,2000})"?""",
    """\ssrc="?({src_ip}[^"\s]{1,2000})"?(\s{1,100}\w+=|\s{0,100}$)""",
    """shost="?(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]{1,2000}))"?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wduser="?(|(({domain}[^\\="]{1,2000})(\\)+)?({user}[^"]{1,2000}?))"?\s{1,100}(\w+=|$)""",
    """\ssuser="?(|(({domain}[^\\="]{1,2000})(\\)+)?({user}[^"]{1,2000}?))"?(\s{1,100}\w+=|\s{0,100}$)""",
    """fname=({additional_info}[^=]{1,2000}?)\s{1,100}\w+=""",
    """({file_type}(?i)file)""",
    """({app}Vault)""",
    """app="?({protocol}SSH)""",
    """reason="?({command_line}[^\n"]{1,2000}?)"?\s{1,100}cs1Label=""",
    """cs3="?({device_type}[^="]{1,2000}?)"?\s{1,100}\w+=""",
    """cs2="?({safe_name}[^="]{1,2000}?)"?\s{1,100}\w+=""",
    """\Wact="?({activity}[^"=\[\]]{1,2000}?)"?(\[|\]|\s{1,100}\w+=|\s{0,100}$)"""
  ]


}
```