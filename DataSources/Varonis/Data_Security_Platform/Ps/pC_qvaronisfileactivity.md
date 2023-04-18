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
  Conditions = [ """LEEF:""", """|Varonis|DatAdvantage|""", """Event_Type=File""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """devTime=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """devTime=({time}\w{1,10}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """accountName =({user}[^=]{1,2000}?)\s{1,10}(\w{1,100}=|$)""",
    """domain=(|({domain}[^=]{1,2000}?))\s{1,10}(\w{1,100}=|$)""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})\s{1,10}(\w{1,100}=|$)""",
    """Event_Type=({accesses}[^=]{1,2000}?)\s{1,10}(\w{1,100}=|$)""",
    """Event_Status=({outcome}[^=]{1,2000}?)\s{1,10}(\w{1,100}=|$)""",
    """Affected_Object=(|({file_path}[^=]{1,2000}?))\s{1,10}(\w{1,100}=|$)""",
    """Affected_Object=(({file_parent}[^=]{1,2000}?)\\{1,10})?({file_name}[^\\]{1,2000}?(\.({file_ext}[^\.\s]{1,2000}))?)\s{1,100}(\w{1,100}=|$)""",
    """Affected_Object_Path=(|({file_path}[^=]{1,2000}?))\s{1,10}(\w{1,100}=|$)""",
    """Affected_Object_Path=({file_parent}[^=]{1,2000}?)\\[^\\]{1,2000}\s{1,10}(\w{1,100}=|$)""",
    """cat=({category}[^=]{1,2000}?)\s{1,10}(\w{1,100}=|$)""",
    """DatAdvantage\|[^\\]{1,1000}?\|({additional_info}[^\\]{1,2000}?)\|""",
    """Device_Name =({src_host}[^=]{1,2000}?)\s{1,10}(\w{1,100}=|$)""",
    """usrName =(({domain}[^\\]{1,100})\\)?({user}[^=]{1,1000}?)\s{1,10}(\w{1,100}=|$)"""
  ]
  DupFields = [ "accesses->event_code" ]


}
```