#### Parser Content
```Java
{
Name = cef-dlp-email-in
  Vendor = Microsoft
  Product = Exchange
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ "|Microsoft|Exchange Server|", "flexString1=Incoming" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\srt=({time}\d+)""",
    """\sdvc=({host}[\d.]+)""",
    """\sdvchost=\[?({host}[^\s\]]*)""",
    """\scs6=({return_path}.+?)\s+\w+=""",
    """\ssuser=({sender}.+?)\s+\w+=""",
    """\ssuser=({external_address}.+?)\s+\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sduser=({orig_user}[^\s]+)""",
    """\ssuser=[^@]+@({external_domain}[^\s;]+)""",
    """\sduser=({recipient}[^\s@;,"]+@[^\s@;,"]+)""",
    """\sduser=({recipients}.+?)\s+\w+=""",
    """\smsg=({subject}.+?)\s+\w+=""",
    """\|RECEIVE\|RECEIVE\|.+?in=({bytes}\d+)""",
    """\|SEND\|SEND\|.+?out=({bytes}\d+)""",
    """\seventId=({alert_id}\d+)"""
    """\ssourceServiceName=({alert_name}[^\s]+)""",
    """\ssourceServiceName=({alert_type}[^\s]+)""",
    """CEF([^\|]*\|){6}({alert_severity}[^|]+)""",
    """CEF([^\|]*\|){5}({action}[^|]+)""",
    """({direction}i)""",
    """\scategoryOutcome=(\/)?({outcome}[^\s]*)"""
  ]
  DupFields = [ "orig_user->user" ]
}

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