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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """<MessageLocalDateTime>({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(AM|PM|am|pm))""",
    """<JournalLogMessageType>({outcome}[^<]+)""",
    """<MessageText>[^<]*?\(Card:\s*({badge_id}[^\)]+)""",
    """<PrimaryObjectName>({last_name}[^<,]+),\s*({first_name}[^<,]+)""",
    """<SecondaryObjectName>({location_door}[^<]+)""",
  ]
}
```