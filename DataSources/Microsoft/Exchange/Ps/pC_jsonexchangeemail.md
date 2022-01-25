#### Parser Content
```Java
{
Name = json-exchange-email
  Vendor = Microsoft
  Product = Exchange
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions =[""""run_id":""", """"sender_address":""", """"recipient_domain":"""]
  Fields =[
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"date_time":"({time}[^"]{1,2000})""",
    """"recipient_address":"({recipient}[^"]{1,2000})""",
    """"email_direction":"({direction}[^"]{1,2000})""",
    """"message_subject":"({subject}.+?)\s{0,100}"""",
    """"attachment_name":"(UNKNOWN|({attachment}[^"]{1,2000}))""",
    """"sender_address":"({sender}[^"]{1,2000})""",
    """"total_bytes":({bytes}\d{1,100})""",
    """"email_event":"({action}[^"]{1,2000})"""
    ]
    DupFields = [ "sender->user_email","user_email->user"]



}
```