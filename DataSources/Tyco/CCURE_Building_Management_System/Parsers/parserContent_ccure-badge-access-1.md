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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """<MessageLocalDateTime>({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm))""",
    """<JournalLogMessageType>({outcome}[^<]{1,2000})""",
    """<MessageText>[^<]{0,2000}?\(Card:\s{0,100}({badge_id}[^\)]{1,2000})""",
    """<PrimaryObjectName>({last_name}[^<,]{1,2000}),\s{0,100}({first_name}[^<,]{1,2000})""",
    """<SecondaryObjectName>({location_door}[^<]{1,2000})""",
  ]
}
```