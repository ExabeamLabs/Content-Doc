#### Parser Content
```Java
{
Name = o365-email-alert
  Vendor = Microsoft
  Product = Office 365
  Lms = Syslog
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """O365 Messages logrhythm:""", """TS=""", """SESSID=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """TS=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """RECIPIENT=({recipient}[^\s]{1,2000})""",
    """SENDER=({sender}[^\s]{1,2000})""",
    """SIP=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """DIP=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """SUBJECT=(|({subject}.+?))\s{1,100}\w+=""",
    """STATUS=({outcome}[^\s]{1,2000})""",
    """SIZE=({bytes}\d{1,100})""",
    """SESSID=({message_id}[^\s]{1,2000})""",
  ]


}
```