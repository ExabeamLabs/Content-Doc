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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\s({host}[\w\-.]+)\s+LEEF:""",
    """LEEF:([^\|]*\|){4}({alert_type}[^\|]+)""",
    """devTime=({time}\w+\s+\d+\s+\d+\s+\d+:\d+:\d+\s+\w+)""",
    """desc=({alert_name}.+?)\s+(\w+=|$)""",
    """sev=({alert_severity}.+?)\s+(\w+=|$)""", 
    """emailSubject=\s*({subject}.+?)\s+(\w+=|$)""", 
    """(sender|Sender)=({sender}.+?)\s+(\w+=|$)""",
    """fname=({file_name}.+?)\s+(\w+=|$)""",
    """EventDetailLink=({additional_info}.+?)\s+(\w+=|$)""",
    """(mailUrlHash|fileHash)=({md5}.+?)\s+(\w+=|$)""",
    """usrName=({user_email}[^\s@]+@[^\s@]+)""",
    """\Wcat=({activity}.+?)\s+(\w+=|$)""",
  ]
  DupFields = [ "user_email->recipient" , "host->dest_host", "sender->target"]
}
```