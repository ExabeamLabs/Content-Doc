#### Parser Content
```Java
{
Name = s-azure-authentication
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """ Access """, """ for user """, """ Azure MFA response: """ ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """\sComputerName=({host}.+?)\s+\w+=""",
    """\sUser=(NOT_TRANSLATED|({user}.+?))\s+\w+=""",
    """Access ({action}.+?) for user ({user_email}[^\s@]+@[^\s@]+)""",
    """Azure MFA response:\s*({failure_reason}\w+)""",
  ]
}
```