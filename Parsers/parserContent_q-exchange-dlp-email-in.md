#### Parser Content
```Java
{
Name = q-exchange-dlp-email-in-1
  Vendor = Microsoft
  Product = Exchange
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """message-subject=""", """TOTAL-HUB=""", """directionality=Incoming""" ]
  Fields = [
    """exabeam_host=([^@=]+@)?\s*({host}[\w-.]+)""",
    """client-ip=({src_ip}[a-fA-F\d.:]+)""",
    """SourceIp=({src_ip}[a-fA-F\d.:]+)""",
    """server-ip=({dest_ip}[a-fA-F\d.:]+)""",
    """server-hostname=({dest_host}[\w.\-]+)""",
    """date-time=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """client-hostname=({src_host}[\w.\-]+)""",
    """\tsource=(?:|({alert_name}.+?))\t[\w\-]+=""",
    """event-id=({outcome}\w+)""",
    """\tinternal-message-id=(?:|({alert_id}.+?))\t[\w\-]+=""",
    """recipient-address=({recipients}\S+)""",
    """recipient-address=({recipient}[^\s;]+)""",
    """total-bytes=({bytes}\d+)""",
    """recipient-count=({num_recipients}\d+)""",
    """message-subject="*({subject}.+?)"*\s+((\w+-)*\w+=|$)""",
    """sender-address=({sender}[^\s@]+@({external_domain}[^@\s]+))""",
    """directionality=({direction}\w+)"""
  ]
  DupFields = [ "alert_name->alert_type", "sender->external_address", "recipient->user", "recipient->orig_user" ]
}
```