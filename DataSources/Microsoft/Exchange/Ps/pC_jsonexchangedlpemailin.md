#### Parser Content
```Java
{
Name = json-exchange-dlp-email-in
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """event_id":""", """directionality":"Incoming"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """date_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z""",
    """client_ip":"(?:|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))",""",
    """client_hostname":"(?:|({src_host}[^\"]{1,2000}))",""",
    """server_ip":"(?:|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))",""",
    """server_hostname":"(?:|({dest_host}[^\"]{1,2000}))",""",
    """exchange_source":"(?:|({alert_name}[^\"]{1,2000}))",""",
    """event_id":"(?:|({action}[^\"]{1,2000}))",""",
    """internal_message_id":"{0,20}(?:|({alert_id}[^",]{1,2000}))"{0,20}
```