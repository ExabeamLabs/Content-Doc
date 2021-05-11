#### Parser Content
```Java
{
Name = q-exchange-dlp-email-out-1
  Vendor = Microsoft
  Product = Exchange
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """message-subject=""", """TOTAL-HUB=""", """directionality=Originating""" ]
  Fields = [
    """exabeam_host=([^@=]+@)?\s{0,100}({host}[\w-.]+)""",
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
    """recipient-address=({recipient}[^\s;@]+@({external_domain}[^@\s;]+))""",
    """total-bytes=({bytes}\d{1,100})""",
    """recipient-count=({num_recipients}\d{1,100})""",
    """message-subject="{0,20}({subject}.+?)"{0,20}\s{1,100}((\w+-)*\w+=|$)""",
    """sender-address=({sender}\S+)""",
    """directionality=({direction}\w+)"""
  ]
  DupFields = [ "alert_name->alert_type", "recipient->external_address", "sender->user", "sender->orig_user" ]
}
```