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
    """\sComputerName =({host}.+?)\s{1,100}\w+=""",
    """\sUser=(NOT_TRANSLATED|({user}.+?))\s{1,100}\w+=""",
    """Access ({action}.+?) for user ({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})""",
    """Azure MFA response:\s{0,100}({failure_reason}\w+)""",
  ]


}
```