#### Parser Content
```Java
{
Name = q-o365-siem-security-alert
    Vendor = Microsoft
    Product = Microsoft Cloud App Security (MCAS)
    Lms = QRadar
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ """|MCAS|SIEM_Agent|""", """CEF:""", """|ALERT_""" ]
    Fields = [
      """({host}[\w\-\.]{1,2000})\s{1,100}CEF:""",
      """\Wrt=({time}\d{1,100})""",
      """CEF:([^\|]{0,2000}?\|){4}({alert_name}[^\|]{1,2000}?)\|""",
      """CEF:([^\|]{0,2000}?\|){5}({alert_type}[^\|]{1,2000}?)\|""",
      """CEF:([^\|]{0,2000}?\|){6}({alert_severity}\d{1,100})""",
      """\WexternalId=({alert_id}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
      """\Wsuser=({user_email}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
      """\Wcs1=({additional_info}.+?)\s{1,100}(\w+=|$)""",
      """DestinationServiceName=({process_name}.*?)\s\w+=""", 
    ]
  }
```