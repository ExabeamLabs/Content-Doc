#### Parser Content
```Java
{
Name = q-varonis-file-activity
  Vendor = Varonis
  Product = Data Security Platform
  Lms = QRadar
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """LEEF:""", """|Varonis|DatAdvantage|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """devTime=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """accountName=({user}.+?)\s{1,100}(\w+=|$)""",
    """domain=(|({domain}.+?))\s{1,100}(\w+=|$)""",
    """src=({dest_ip}[A-Fa-f:\d.]{1,2000})\s{1,100}(\w+=|$)""",
    """Event_Type=({accesses}.+?)\s{1,100}(\w+=|$)""",
    """Event_Status=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """Affected_Object=(|({file_path}.+?))\s{1,100}(\w+=|$)""",
    """Affected_Object=(({file_parent}[^=]{1,2000}?)\\+)?({file_name}[^\\]{1,2000}?(\.({file_ext}[^\.\s]{1,2000}))?)\s{1,100}(\w+=|$)""",
    """Affected_Object_Path=(|({file_path}.+?))\s{1,100}(\w+=|$)""",
    """Affected_Object_Path=({file_parent}.+?)\\[^\\]{1,2000}\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "accesses->event_code" ]
}
```