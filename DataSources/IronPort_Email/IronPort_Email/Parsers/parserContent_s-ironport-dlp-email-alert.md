#### Parser Content
```Java
{
Name = s-ironport-dlp-email-alert
    Vendor = IronPort Email
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """Message done DCID""", """'from'""", """'to'""" ]
    Fields = [
      """\srt=({time}\d+)""",
      """\W({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\-\d\d:\d\d)\s({host}[^\s]+)\s""",
      """\WMessage done DCID \d+ MID ({alert_id}\d+)\s""",
      """\('from',\s*'({user}.*?)'\)""",
      """\('from',\s*'.*?<({user}.*?)>'\)""",
      """\('to',\s*'({recipients}.*?)'\)""",
      """\('to',\s*'.*?<({recipients}.*?)>'\)""",
      """\('to',\s*'[\<]?({recipient}[^>,\';]+)""",
      """\('to',\s*'[\"][^\<]+[\<]?({recipient}[^>,\';]+)""",
      """\('to',\s*'({external_address}[^@<>]+@({external_domain}[^>,<']+)).*?'\)""",
      """\('to',\s*'.*?<({external_address}[^@><]+@({external_domain}[^>,<']+)).*?'\)""",
      """\('(subject|Subject)',\s*'({subject}.*?)'\)""",
      """\('(x-fr({direction}o)m-mailhub|X-Fr({=direction}o)m-MailHub)',\s*'true'\)"""
    ]
    DupFields = [ "user->sender" ]
  }
```