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
      """({host}[\w\-\.]+)\s+CEF:""",
      """\Wrt=({time}\d+)""",
      """CEF:([^\|]*?\|){4}({alert_name}[^\|]+?)\|""",
      """CEF:([^\|]*?\|){5}({alert_type}[^\|]+?)\|""",
      """CEF:([^\|]*?\|){6}({alert_severity}\d+)""",
      """\WexternalId=({alert_id}[^\s]+)\s+(\w+=|$)""",
      """\Wsuser=({user_email}[^\s]+)\s+(\w+=|$)""",
      """\Wcs1=({additional_info}.+?)\s+(\w+=|$)""",
      """DestinationServiceName=({process_name}.*?)\s\w+=""", 
    ]
  }
```