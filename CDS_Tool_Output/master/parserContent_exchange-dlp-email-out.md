#### Parser Content
```Java
{
Name = exchange-dlp-email-out-failed
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """,Originating,""", """,FAIL,""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z,[^,]*,({host}[^,]+),([^,]*,){5}FAIL,""",
    """({additional_info}\w+,FAIL),""",
    """({action}FAIL)""",
    """,FAIL,\s*({alert_id}\d+)""",
    """,\s*(?:'|")?({recipients}({recipient}[^,;'"\s@]+@({external_domain}[^,;'"\s@]+))[^,]*?)\s*(?:'|")?,([^,]*,){9}Originating,""",
    """,\s*(({bytes}\d+)|)\s*,\s*(({num_recipients}\d+)|)\s*,([^,]*,){6}Originating,""",
    """,\s*({subject}[^,]+?)\s*,([^,]*,){3}Originating,""",
    """,\s*'({subject}(?:[^']|'')+?)\s*'\s*,([^,]*,){3}Originating,""",
    """,\s*"({subject}(?:[^"]|"")+?)\s*"\s*,([^,]*,){3}Originating,""",
    """,\s*(?:'|")?(|MicrosoftExchange.*?|({user_email}[^,]+?)(?:'|")?)\s*,([^,]*,){2}Originating,""",
    """,\s*(?:'|")?(?:<>|({return_path}[^,]+?))(?:'|")?\s*,([^,]*,)Originating,""",]
DupFields = [
    "user_email->sender",
    "user_email->orig_user",
    "recipient->external_address",
    "action->outcome"
  ]
}
```