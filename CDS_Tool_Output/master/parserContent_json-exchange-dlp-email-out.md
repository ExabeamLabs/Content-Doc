#### Parser Content
```Java
{
Name = json-exchange-dlp-email-out
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """event_id":""", """directionality":"Originating"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """date_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z""",
    """client_ip":"(?:|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))",""",
    """client_hostname":"(?:|({src_host}[^\"]+))",""",
    """server_ip":"(?:|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))",""",
    """server_hostname":"(?:|({dest_host}[^\"]+))",""",
    """exchange_source":"(?:|({alert_name}[^\"]+))",""",
    """event_id":"(?:|({action}[^\"]+))",""",
    """internal_message_id":"*(?:|({alert_id}[^",]+))"*,""",
    """recipient_address":"(?:|({recipients}[^\"]+))",""",
    """recipient_address":"(?:|({external_address}[^,;@]+@[^;,"']+))",""",
    """recipient_address":"[^@]+@({external_domain}[^";,]+)""",
    """total_bytes":"*(?:|({bytes}\d+))"*,""",
    """recipient_count":"*(?:|({num_recipients}\d+))"*,""",
    """message_subject":"(?:|({subject}[^\"]+))",""",
    """sender_address":"(?:|({sender}[^\"]+))",""",
    """return_path":"(?:|<>|({return_path}[^\"]+))",""",
  ]
  DupFields = [
    "alert_name->alert_type",
    "sender->email_user",
    "action->outcome"
  ]
}
```