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
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\srt=({time}\d+)""",
    """({time}\w+ \d+ \d\d:\d\d:\d\d) mail_logs:""",
    """direction=({direction}[^,]+)""",
    """From:\s*<({sender}[^\s@>]+@[^\s@>]+)""",
    """To:\s*<({recipients}({recipient}[^\s@>;,]+@[^\s@>;,]+)[^>]*)""",
    """(?i)(Subject)[\s\\=]*"({subject}[^"]+)""",
    """({time}\d+\/\d+\/\d\d\d\d\s+\d\d:\d\d:\d\d\s+[\+\-]\d+)""",
    """Message finished MID ({alert_id}\d+) ({outcome}aborted|done)""",
    """MID \d+ ready ({bytes}\d+) bytes from """,
    """AMP file reputation verdict\s*:\s*(UNKNOWN|({file_verdict}.+?))\s+\w+\s+\w+\s+\d+\s+\d+:\d+:\d+""",
    """MID\s*\d+\s*attachment\s*'({attachment}[^']+)""",
    """interim AV verdict using.+?({malware_score}\S+)\s+\w+\s+\w+\s+\d+\s+\d+:\d+:\d+""",
    """using engine: GRAYMAIL ({graymail_score}\S+)""",
    """CASE spam ({spam_score}\S+)""",
    """antivirus ({malware_score}\S+)""",
    """\Wfname=(|({attachment}.*?))\s+(\w+=|$)""",
  ]
}
```