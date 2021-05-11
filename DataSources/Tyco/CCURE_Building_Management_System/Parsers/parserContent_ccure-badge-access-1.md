#### Parser Content
```Java
{
Name = ccure-badge-access-1
  Vendor = Tyco
  Product = CCURE Building Management System
  Lms = ArcSight
  DataType = "physical-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """<JournalLogMessageType>""", """<OperatorName>ccure<""", """<MessageText>""", """<PrimaryObjectName>""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """<MessageLocalDateTime>({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm))""",
    """<JournalLogMessageType>({outcome}[^<]+)""",
    """<MessageText>[^<]*?\(Card:\s{0,100}({badge_id}[^\)]+)""",
    """<PrimaryObjectName>({last_name}[^<,]+),\s{0,100}({first_name}[^<,]+)""",
    """<SecondaryObjectName>({location_door}[^<]+)""",
  ]
}
```