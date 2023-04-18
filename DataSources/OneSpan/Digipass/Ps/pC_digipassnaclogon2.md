#### Parser Content
```Java
{
Name = digipass-nac-logon-2
  Vendor = OneSpan
  Product = Digipass
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """Source Location """, """Event:""", """AMID:""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """Timestamp:\s({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d)""",
    """Event:\s{1,100}\[[^\]]{1,2000}\]\s({event_name}[^:]{1,2000})\.\s\w+:""",
    """User ID\s{0,20}:\s{0,20}({user}[^\

}
```