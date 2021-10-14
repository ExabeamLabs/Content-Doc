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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z,[^,]{0,2000},({host}[^,]{1,2000}),([^,]{0,2000},){5}FAIL,""",
    """({additional_info}\w+,FAIL),""",
    """({action}FAIL)""",
    """,FAIL,\s{0,100}({alert_id}\d{1,100})""",
    """,\s{0,100}(?:'|")?([^,]{1,2000}Recipients_cn\=)?({recipients}({recipient}[^,;'"\s@]{1,2000}@[^,;'"\s@]{1,2000})[^,]{0,2000}?)\s{0,100}(?:'|")?,([^,]{0,2000},){9}Originating,""",
    """,\s{0,100}(({bytes}\d{1,100})|)\s{0,100},\s{0,100}(({num_recipients}\d{1,100})|)\s{0,100},([^,]{0,2000},){6}Originating,""",
    """,\s{0,100}({subject}[^,]{1,2000}?)\s{0,100},([^,]{0,2000},){3}Originating,""",
    """,\s{0,100}'({subject}(?:[^']|'')+?)\s{0,100}'\s{0,100},([^,]{0,2000},){3}Originating,""",
    """,\s{0,100}"({subject}(?:[^"]|"")+?)\s{0,100}"\s{0,100},([^,]{0,2000},){3}Originating,""",
    """,\s{0,100}(?:'|")?(|MicrosoftExchange.*?|({user_email}[^,]{1,2000}?)(?:'|")?)\s{0,100},([^,]{0,2000},){2}Originating,""",
    """,\s{0,100}(?:'|")?(?:<>|({return_path}[^,]{1,2000}?))(?:'|")?\s{0,100},([^,]{0,2000},)Originating,""",]
DupFields = [
    "user_email->sender",
    "user_email->orig_user",
    "recipient->external_address",
    "action->outcome"
  ]
}
```