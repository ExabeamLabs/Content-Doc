#### Parser Content
```Java
{
Name = s-ironport-dlp-email-alert
    Vendor = Cisco
  Product = IronPort Email
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """Message done DCID""", """'from'""", """'to'""" ]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\W({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\-\d\d:\d\d)\s({host}[^\s]{1,2000})\s""",
      """\WMessage done DCID \d{1,100} MID ({alert_id}\d{1,100})\s""",
      """\('from',\s{0,100}'({user}.*?)'\)""",
      """\('from',\s{0,100}'.*?<({user}.*?)>'\)""",
      """\('to',\s{0,100}'({recipients}.*?)'\)""",
      """\('to',\s{0,100}'.*?<({recipients}.*?)>'\)""",
      """\('to',\s{0,100}'[\<]?({recipient}[^>,\';]{1,2000})""",
      """\('to',\s{0,100}'[\"][^\<]{1,2000}[\<]?({recipient}[^>,\';]{1,2000})""",
      """\('to',\s{0,100}'({external_address}[^@<>]{1,2000}@({external_domain}[^>,<']{1,2000})).*?'\)""",
      """\('to',\s{0,100}'.*?<({external_address}[^@><]{1,2000}@({external_domain}[^>,<']{1,2000})).*?'\)""",
      """\('(subject|Subject)',\s{0,100}'({subject}.*?)'\)""",
      """\('(x-fr({direction}o)m-mailhub|X-Fr({=direction}o)m-MailHub)',\s{0,100}'true'\)"""
    ]
    DupFields = [ "user->sender" ]
  

}
```