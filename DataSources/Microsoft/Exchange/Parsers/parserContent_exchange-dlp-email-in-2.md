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
    """,({time}\d\d\d\d-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d+)""",
    """\d+:\d+\.\d+Z,[A-Fa-f:\d.]+,({host}[\w\.\-]+),""",
    """({additional_info}SMTP),({action}[^,]+),({alert_id}\d+),""",
    """({direction}Incoming)""",
    """,({recipients}({recipient}[^\s@;,"]+@({external_domain}[^\s@;,"]+))[^,]*?),(?:[^",]+?,|,)({bytes}\d+),({num_recipients}\d+),(?:"(?:[^"]|"")+",|[^",]+?,|,){6}Incoming,""",
    """,\s*({subject}[^,]*?)\s*,(?:[^",]+?,|,){3}Incoming,""",
    ""","\s*({subject}[^"]+?)\s*",(?:[^",]+?,|,){3}Incoming,""",
    """,(MicrosoftExchange[^,]+?|({external_address}[^\s,;@"']+@({external_domain}[^\s;,"'@]+))),(?:<>|({return_path}[^,]+?)),(?:[^",]+?,|,)Incoming,"""
  ]
  DupFields = [ "recipient->orig_user", "recipient->user_email", "external_address->sender" ]
}
```