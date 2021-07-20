#### Parser Content
```Java
{
Name = leef-lastline-security-alert
  Vendor = Lastline
  Product = Lastline
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Conditions = [ """LEEF:""", """|Lastline|Enterprise|""", """deviceExternalId=""", """devTime=""", """|email-""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\s({host}[\w\-.]{1,2000})\s{1,100}LEEF:""",
    """LEEF:([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})""",
    """devTime=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\w+)""",
    """desc=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """sev=({alert_severity}.+?)\s{1,100}(\w+=|$)""", 
    """emailSubject=\s{0,100}({subject}.+?)\s{1,100}(\w+=|$)""", 
    """(sender|Sender)=({sender}.+?)\s{1,100}(\w+=|$)""",
    """fname=({file_name}.+?)\s{1,100}(\w+=|$)""",
    """EventDetailLink=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """(mailUrlHash|fileHash)=({md5}.+?)\s{1,100}(\w+=|$)""",
    """usrName=({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})""",
    """\Wcat=({activity}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "user_email->recipient" , "host->dest_host", "sender->target"]
}
```