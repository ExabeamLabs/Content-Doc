#### Parser Content
```Java
{
Name = exchange-dlp-email-in-2
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:m:ss.SSS"
  Conditions = [ """,SMTP,SEND,""", """,Incoming,""" ]
  Fields = [
    """,({time}\d\d\d\d-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d{1,100})""",
    """\d{1,100}:\d{1,100}\.\d{1,100}Z,[A-Fa-f:\d.]{1,2000},({host}[\w\.\-]{1,2000}),""",
    """({additional_info}SMTP),({action}[^,]{1,2000}),({alert_id}\d{1,100}),""",
    """({direction}Incoming)""",
    """,({recipients}({recipient}[^\s@;,"]{1,2000}@[^\s@;,"]{1,2000})[^,]{0,2000}?),(?:[^",]{1,2000}?,|,)({bytes}\d{1,100}),({num_recipients}\d{1,100}),(?:"(?:[^"]|"")+",|[^",]{1,2000}?,|,){6}Incoming,""",
    """,\s{0,100}({subject}[^,]{0,2000}?)\s{0,100},(?:[^",]{1,2000}?,|,){3}Incoming,""",
    ""","\s{0,100}({subject}[^"]{1,2000}?)\s{0,100}",(?:[^",]{1,2000}?,|,){3}Incoming,""",
    """,(MicrosoftExchange[^,]{1,2000}?|({external_address}[^\s,;@"']{1,2000}@[^\s;,"'@]{1,2000})),(?:<>|({return_path}[^,]{1,2000}?)),(?:[^",]{1,2000}?,|,)Incoming,"""
  ]
  DupFields = [ "recipient->orig_user", "recipient->user_email", "external_address->sender" ]
}
```