#### Parser Content
```Java
{
Name = exchange-dlp-email-in
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """,Incoming,""", """,STOREDRIVER,""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){6}STOREDRIVER,""",
    """,({host}[^\s,]+),(?:(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|,){3}STOREDRIVER,""",
    """,[^\s,]+:({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){3}STOREDRIVER,""",
    """,\s*(?:'|")?({host}[\w\.-]+)(?:'|")?\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){2}STOREDRIVER,""",
    """({alert_name}STOREDRIVER,({action}[^,]+)),""",
    """({direction}Incoming)""",
    """,STOREDRIVER,[^,]+,\s*({alert_id}\d+)\s*,""",
    """,\s*(?:'|")?({recipients}[^,]+?)\s*(?:'|")?,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){9}Incoming,""",
    """,\s*(?:'|")?({orig_user}[^,;@]+@[^;,"']+)[^,]*?\s*(?:'|")?,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){9}Incoming,""",
    """,\s*({bytes}\d+)\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){7}Incoming,""",
    """,\s*({num_recipients}\d+)\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){6}Incoming,""",
    """,\s*({subject}[^,]+)\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){3}Incoming,""",
    """,\s*'({subject}(?:[^']|'')+)'\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){3}Incoming,""",
    """,\s*"({subject}(?:[^"]|"")+)"\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){3}Incoming,""",
    """,\s*(?:'|")?(|MicrosoftExchange.*?|({sender}[^,]+?)(?:'|")?)\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){2}Incoming,""",
    """,\s*(?:'|")?(|.+?@({external_domain}[^,]+?)(?:'|")?)\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){2}Incoming,""",
    """,\s*(?:'|")?(?:<>|({return_path}[^,]+?))(?:'|")?\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,)Incoming,""",
  ]
  DupFields = [
    "sender->external_address",
    "alert_name->alert_type",
    "orig_user->user_email",
    "recipients->recipient"
  ]
}
```