#### Parser Content
```Java
{
Name = exchange-dlp-email-in-sd
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """,STOREDRIVER,DELIVER,""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){6}STOREDRIVER,DELIVER,""",
    """,({host}[^\s,]+),(?:(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|,){3}STOREDRIVER,DELIVER,""",
    """,[^\s,]+:({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){3}STOREDRIVER,DELIVER,""",
    """,\s*(?:'|")?({host}[\w\.-]+)(?:'|")?\s*,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){2}STOREDRIVER,DELIVER,""",
    """({alert_name}STOREDRIVER,DELIVER)"""
    """,STOREDRIVER,DELIVER,\s*({alert_id}\d+)\s*,""",
    """,STOREDRIVER,DELIVER,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){2}\s*(?:'|")?({recipients}[^,]+?)\s*(?:'|")?,""",
    """,STOREDRIVER,DELIVER,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){2}\s*(?:'|")?({orig_user}[^;@]+@[^;,"']+)[^,]*?\s*(?:'|")?,""",
    """,STOREDRIVER,DELIVER,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){4}\s*({bytes}\d+)\s*,""",
    """,STOREDRIVER,DELIVER,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){5}\s*({num_recipients}\d+)\s*,""",
    """,STOREDRIVER,DELIVER,(?:(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){8}\s*({subject}[^,]+)\s*,""",
    """,STOREDRIVER,DELIVER,(?:(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){8}\s*'({subject}(?:[^']|'')+)'\s*,""",
    """,STOREDRIVER,DELIVER,(?:(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){8}\s*"({subject}(?:[^"]|"")+)"\s*,""",
    """,STOREDRIVER,DELIVER,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){9}\s*(?:'|")?(|MicrosoftExchange.*?|({sender}[^,]+?)(?:'|")?)\s*,""",
    """,STOREDRIVER,DELIVER,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){9}\s*(?:'|")?(|.+?@({external_domain}[^,]+?)(?:'|")?)\s*,""",
    """,STOREDRIVER,DELIVER,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){10}\s*(?:'|")?(?:<>|({return_path}[^,]+?))(?:'|")?\s*,""",
  ]
  DupFields = [ "orig_user->user", "sender->external_address", "alert_name->alert_type" ]
}

{
  Name = exchange-dlp-email-out-sd
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """,STOREDRIVER,RECEIVE,""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){6}STOREDRIVER,RECEIVE,""",
    """,({host}[^\s,]+),(?:(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|,){3}STOREDRIVER,RECEIVE,""",
    """,[^\s,]+:({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){3}STOREDRIVER,RECEIVE,""",
    """,\s*(?:'|")?({host}[\w\.-]+)(?:'|")?\s*,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){2}STOREDRIVER,RECEIVE,""",
    """({additional_info}STOREDRIVER,RECEIVE)"""
    """,STOREDRIVER,RECEIVE,\s*({alert_id}\d+)\s*,""",
    """,STOREDRIVER,RECEIVE,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){2}\s*(?:'|")?({recipients}[^,]+?)\s*(?:'|")?,""",
    """,STOREDRIVER,RECEIVE,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){2}\s*(?:'|")?({external_address}[^;@]+@[^;,"']+)[^,]*?\s*(?:'|")?,""",
    """,STOREDRIVER,RECEIVE,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){2}\s*(?:'|")?[^;@]+@({external_domain}[^;,"']+)[^,]*?\s*(?:'|")?,""",
    """,STOREDRIVER,RECEIVE,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){4}\s*({bytes}\d+)\s*,""",
    """,STOREDRIVER,RECEIVE,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){5}\s*({num_recipients}\d+)\s*,""",
    """,STOREDRIVER,RECEIVE,(?:(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){8}\s*({subject}[^,]+)\s*,""",
    """,STOREDRIVER,RECEIVE,(?:(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){8}\s*'({subject}(?:[^']|'')+)'\s*,""",
    """,STOREDRIVER,RECEIVE,(?:(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){8}\s*"({subject}(?:[^"]|"")+)"\s*,""",
    """,STOREDRIVER,RECEIVE,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){9}\s*(?:'|")?({user_email}[^,]+?)(?:'|")?\s*,""",
    """,STOREDRIVER,RECEIVE,(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,){10}\s*(?:'|")?(?:<>|({return_path}[^,]+?))(?:'|")?\s*,""",
  ]
  DupFields = [ "user_email->sender", "recipients->recipient" ]
}
```