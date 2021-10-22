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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z,(?:(?:\s{0,100}'+[^']{0,2000}'+)\s{0,100},|(?:\s{0,100}"{1,20}[^"]{0,2000}"{1,20})\s{0,100},|[^",]{1,2000}?,|\s{0,100},){6}STOREDRIVER,""",
    """,\s{0,100}['"]{0,100}({host}[\w\.-]{1,2000})['"]{0,100}\s{0,100},([^,]{0,2000},){2}STOREDRIVER,""",
    """({alert_name}STOREDRIVER,({action}[^,]{1,2000})),""",
    """({direction}Incoming)""",
    """,STOREDRIVER,[^,]{1,2000},\s{0,100}({alert_id}\d{1,100})\s{0,100},""",
    """,\s{0,100}['"]{0,100}({recipients}[^,;@]{1,2000}@[^;,"']{1,2000}?)\s{0,100}['"]{0,100},(?:[^,]{0,2000},){9}Incoming,""",
    """,\s{0,100}['"]{0,100}({orig_user}[^,;@]{1,2000}@[^;,"']{1,2000})\s{0,100}['"]{0,100},([^,]{0,2000},){9}Incoming,""",
    """,\s{0,100}({bytes}\d{1,100})\s{0,100},(?:[^,]{0,2000},){7}Incoming,""",
    """,\s{0,100}({num_recipients}\d{1,100})\s{0,100},(?:[^,]{0,2000},){6}Incoming,""",
    """,\s{0,100}({subject}[^,]{1,2000}?)\s{0,100},(?:[^,]{0,2000},){3}Incoming,""",
    """,\s{0,100}['"]{0,100}(|MicrosoftExchange.*?|({sender}[^,]{1,2000}?)['"]{0,100})\s{0,100},(?:[^,]{0,2000},){2}Incoming,""",
    """,\s{0,100}['"]{0,100}(|.+?@({external_domain}[^,]{1,2000}?)['"]{0,100})\s{0,100},(?:[^,]{0,2000},){2}Incoming,""",
    """,\s{0,100}['"]{0,100}(?:<>|({return_path}[^,]{1,2000}?))['"]{0,100}\s{0,100},(?:[^,]{0,2000},)Incoming,""",
  ]
  DupFields = [
    "sender->external_address",
    "alert_name->alert_type",
    "orig_user->user_email",
    "recipients->recipient"
  ]
}
```