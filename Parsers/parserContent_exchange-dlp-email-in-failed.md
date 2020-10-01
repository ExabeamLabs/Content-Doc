#### Parser Content
```Java
{
Name = exchange-dlp-email-in-failed
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """,Incoming,""", """,FAIL,""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z,[^,]*,({host}[^,]+),([^,]*,){5}FAIL,""",
    """,({host}[^\s,]+),([^,]*,){3}\w+,FAIL,""",
    """,[^\s,]+:({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),([^,]*,){3}\w+,FAIL,""",
    """,\s*(?:'|")?({host}[\w\.-]+)(?:'|")?\s*,([^,]*,){2}\w+,FAIL,""",
    """({additional_info}\w+,FAIL),\s*(({alert_id}\d+)|)\s*,""",
    """({action}FAIL)""",
    """,\s*(?:'|")?({recipients}({recipient}[^,;'"\s@]+@[^,;'"\s@]+)[^,]*?)\s*(?:'|")?,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){9}Incoming,""",
    """,\s*(?:'|")?({orig_user}[^,;@]+@[^;,"']+)[^,]*?\s*(?:'|")?,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){9}Incoming,""",
    """,\s*(({bytes}\d+)|)\s*,\s*(({num_recipients}\d+)|)\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){6}Incoming,""",
    """,\s*({subject}[^,]+?)\s*,([^,]*,){3}Incoming,""",
    """,\s*'({subject}(?:[^']|'')+?)\s*'\s*,([^,]*,){3}Incoming,""",
    """,\s*"({subject}(?:[^"]|"")+?)\s*"\s*,([^,]*,){3}Incoming,""",
    """,\s*(?:'|")?(|MicrosoftExchange.*?|({sender}[^,@]+?@({external_domain}[^,]+?))(?:'|")?)\s*,([^,]*,){2}Incoming,""",
    """,\s*(?:'|")?(?:<>|({return_path}[^,]+?))(?:'|")?\s*,([^,]*,)Incoming,""",
    """({direction}Incoming)""",
]
  DupFields = [
    "sender->external_address",
    "orig_user->user_email",
    "action->outcome"
  ]
}
```