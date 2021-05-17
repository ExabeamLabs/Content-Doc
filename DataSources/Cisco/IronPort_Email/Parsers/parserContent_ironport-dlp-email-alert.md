#### Parser Content
```Java
{
Name = ironport-dlp-email-alert
  Vendor = Cisco
  Product = IronPort Email
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss Z"
  Conditions = [ """ Info: MID """, """From:""", """To:""", """Subject""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\srt=({time}\d{1,100})""",
    """({time}\w+ \d{1,100} \d\d:\d\d:\d\d) mail_logs:""",
    """direction=({direction}[^,]{1,2000})""",
    """From:\s{0,100}<({sender}[^\s@>]{1,2000}@[^\s@>]{1,2000})""",
    """To:\s{0,100}<({recipients}({recipient}[^\s@>;,]{1,2000}@[^\s@>;,]{1,2000})[^>]{0,2000})""",
    """(?i)(Subject)[\s\\=]{0,2000}"({subject}[^"]{1,2000})""",
    """({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\s{1,100}[\+\-]\d{1,100})""",
    """Message finished MID ({alert_id}\d{1,100}) ({outcome}aborted|done)""",
    """MID \d{1,100} ready ({bytes}\d{1,100}) bytes from """,
    """AMP file reputation verdict\s{0,100}:\s{0,100}(UNKNOWN|({file_verdict}.+?))\s{1,100}\w+\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}""",
    """MID\s{0,100}\d{1,100}\s{0,100}attachment\s{0,100}'({attachment}[^']{1,2000})""",
    """interim AV verdict using.+?({malware_score}\S+)\s{1,100}\w+\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}""",
    """using engine: GRAYMAIL ({graymail_score}\S+)""",
    """CASE spam ({spam_score}\S+)""",
    """antivirus ({malware_score}\S+)""",
    """\Wfname=(|({attachment}.*?))\s{1,100}(\w+=|$)""",
  ]
}
```