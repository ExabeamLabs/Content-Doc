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
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """devTime=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
    """accountName=({user}.+?)\s+(\w+=|$)""",
    """domain=(|({domain}.+?))\s+(\w+=|$)""",
    """src=({dest_ip}[A-Fa-f:\d.]+)\s+(\w+=|$)""",
    """Event_Type=({accesses}.+?)\s+(\w+=|$)""",
    """Event_Status=({outcome}.+?)\s+(\w+=|$)""",
    """Affected_Object=(|({file_path}.+?))\s+(\w+=|$)""",
    """Affected_Object=(({file_parent}[^=]+?)\\+)?({file_name}[^\\]+?(\.({file_ext}[^\.\s]+))?)\s+(\w+=|$)""",
    """Affected_Object_Path=(|({file_path}.+?))\s+(\w+=|$)""",
    """Affected_Object_Path=({file_parent}.+?)\\[^\\]+\s+(\w+=|$)""",
  ]
  DupFields = [ "accesses->event_code" ]
}
```