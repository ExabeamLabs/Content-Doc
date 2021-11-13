#### Parser Content
```Java
{
Name = q-exchange-dlp-email-in-5
  Conditions = [ """event-id=SEND""", """directionality=Incoming""" ]

q-exchange-dlp-email-in = {
  Vendor = Microsoft
  Product = Exchange
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """exabeam_host=([^@=]{1,2000}@)?\s{0,100}({host}[\w-.]{1,2000})""",
    """\tdate-time=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\tclient-ip=(?:|({src_ip}[A-Fa-f:\d.]{1,2000}))\s""",
    """\tclient-hostname=(?:|({src_host}[\w\-.]{1,2000}))\t[\w\-]{1,2000}=""",
    """\tserver-ip=(?:|({dest_ip}[A-Fa-f:\d.]{1,2000}))\s""",
    """\tserver-hostname=(?:|({dest_host}[\w\-.]{1,2000}))\t[\w\-]{1,2000}=""",
    """\tsource=(?:|({alert_name}.+?))\t[\w\-]{1,2000}=""",
    """\tevent-id=(?:|({action}.+?))\t[\w\-]{1,2000}=""",
    """\tinternal-message-id=(?:|({alert_id}.+?))\t[\w\-]{1,2000}=""",
    """\trecipient-address="?(?:|({recipients}({recipient}[^\s@";,]{1,2000}@[^\s@";,]{1,2000}).*?))"?\t[\w\-]{1,2000}=""",
    """\trecipient-address="?(?:|({user_email}.+?))(;|\t[\w\-]{1,2000}=)""",
    """\ttotal-bytes=(?: |({bytes}\d{1,100}))""",
    """\trecipient-count=(?: |({num_recipients}\d{1,100}))""",
    """message-subject="?\s{0,100}(?:|({subject}.+?))\s{0,100}(\"|[\t\s]{0,2000}[\w\-]{1,2000}=)""",
    """\tsender-address=(?:|({sender}.+?))\t[\w\-]{1,2000}=""",
    """\tsender-address=(?:|({external_address}.+?))\t[\w\-]{1,2000}=""",
    """\treturn-path=(?:|<>|({return_path}.+?))\t[\w\-]{1,2000}=""",
    """\sevent-id=({outcome}[^\s]{1,2000})""",
  ]
  DupFields = [
    "alert_name->alert_type",
    "user_email->orig_user" 
  
}
```