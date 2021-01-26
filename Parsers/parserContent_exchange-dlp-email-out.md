#### Parser Content
```Java
{
Name = exchange-dlp-email-out
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """,Originating,""", """,STOREDRIVER,""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){6}STOREDRIVER,""",
    """,({host}[^\s,]+),(?:(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|,){3}STOREDRIVER,""",
    """,[^\s,]+:({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){3}STOREDRIVER,""",
    """,\s*(?:'|")?({host}[\w\.-]+)(?:'|")?\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){2}STOREDRIVER,""",
    """({additional_info}STOREDRIVER,({action}[^,]+)),""",
    """({direction}Originating)""",
    """,STOREDRIVER,[^,]+,\s*({alert_id}\d+)\s*,""",
    """,\s*({subject}[^,]+)\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){3}Originating,""",
    """,\s*'({subject}(?:[^']|'')+)'\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){3}Originating,""",
    """,\s*"({subject}(?:[^"]|"")+)"\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){3}Originating,""",
    """,\s*(?:'|")?(|MicrosoftExchange.*?|({sender}[^,]+?)(?:'|")?)\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,){2}Originating,""",
    """,\s*(?:'|")?(?:<>|({return_path}[^,]+?))(?:'|")?\s*,(?:(?:\s*'+[^']*'+)\s*,|(?:\s*"+[^"]*"+)\s*,|[^",]+?,|\s*,)Originating,""",
    """,\s*(?:'|")?(([^,]+Recipients_cn\=)?({recipients}[^,]+?))\s*(?:'|")?,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){9}Originating,""",
    """,\s*(?:'|")?([^,]+Recipients_cn\=)?(({recipients}[^,;]+?);[^,]+?)\s*(?:'|")?,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){9}Originating,""",
    """,\s*(?:'|")?([^,]+Recipients_cn\=)?({external_address}[^,;@]+@[^;,"']+)[^,]*?\s*(?:'|")?,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){9}Originating,""",
    """,\s*(?:'|")?[^,;@]+@({external_domain}[^;,"']+)[^,]*?\s*(?:'|")?,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){9}Originating,""",
    """,\s*({bytes}\d+)\s*,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){7}Originating,""",
    """,\s*({num_recipients}\d+)\s*,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){6}Originating,""",
]
  DupFields = [ 
    "sender->orig_user",
    "sender->user_email",
    "recipients->recipient"
    "action->outcome"
  ]
}
```