#### Parser Content
```Java
{
Name = leef-digitalguardian-dlp-email-alert-out
  Vendor = Digital Guardian
  Product = Digital Guardian Network DLP
  Lms = QRadar
  DataType = "dlp-email-alert"
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|Send Mail|""" ]

leef-digitalguardian-dlp-email-alert-out = {
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]{1,2000}) LEEF:""",
    """accountName =(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000}?)\s{0,100}(\w+=|$)""",
    """IdentHostName =(({domain}[^\\])+\\+)?({dest_host}[\w\-.]{1,2000}?)\s{0,100}(\w+=|$)""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """EmailSender=({sender}.+?)\s{0,100}(\w+=|$)""",
    """usrName =(?![^\s]{1,2000}@[^\s]{1,2000})(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s@]{1,2000})\s{0,100}(\w+=|$)""",
    """usrName =(?=[^\s]{1,2000}@[^\s]{1,2000})({user_email}[^\s@]{1,2000}@[^\s]{1,2000})""",
    """EmailRecipient=(|({recipient}[^\s,;]{1,2000}))""",
    """EmailRecipient=(|({recipients}.+?))\s{0,100}(\w+=|$)""",
    """EmailRecipient=({external_address}[^@]{1,2000}@[^@\s,;]{1,2000}).*?\s{0,100}(\w+=|$)""",
    """EmailSubject=(|({subject}.+?))\s{0,100}(\w+=|$)""",
    """sev=({alert_severity}\d{1,100})""",
    """srcBytes=({bytes}\d{1,100})""",
    """FileSizeMB=({bytes_num}\d{1,100})""",
    """FileSize({bytes_unit}MB)""",
    """DestinationFile=(|({attachments}[^\.]{1,2000}\.({file_ext}.+?)))\s{0,100}(\w+=|$)""",
  
}
```