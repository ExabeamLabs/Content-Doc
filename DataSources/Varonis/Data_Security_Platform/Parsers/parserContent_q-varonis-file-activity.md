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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """devTime=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """accountName=({user}.+?)\s{1,100}(\w+=|$)""",
    """domain=(|({domain}.+?))\s{1,100}(\w+=|$)""",
    """src=({dest_ip}[A-Fa-f:\d.]+)\s{1,100}(\w+=|$)""",
    """Event_Type=({accesses}.+?)\s{1,100}(\w+=|$)""",
    """Event_Status=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """Affected_Object=(|({file_path}.+?))\s{1,100}(\w+=|$)""",
    """Affected_Object=(({file_parent}[^=]+?)\\+)?({file_name}[^\\]+?(\.({file_ext}[^\.\s]+))?)\s{1,100}(\w+=|$)""",
    """Affected_Object_Path=(|({file_path}.+?))\s{1,100}(\w+=|$)""",
    """Affected_Object_Path=({file_parent}.+?)\\[^\\]+\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "accesses->event_code" ]
}
```