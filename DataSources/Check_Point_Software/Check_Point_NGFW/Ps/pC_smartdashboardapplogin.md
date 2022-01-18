#### Parser Content
```Java
{
Name = smartdashboard-app-login
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """|product=SmartDashboard|""", """|Subject=Administrator Login|""" ]
  Fields = [
    """\|Administrator=({user}[^\|]{1,2000})\|""",
    """\|time=({time}\d{1,100}\w+\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """\|client_ip=(?:({src_ip}[a-fA-F\d.:]{1,2000})|({src_host}[\w.\-]{1,2000}))\|""",
    """\|Machine=({host}[^\|]{1,2000})\|"""
    """\|Additional Info=({additional_info}[^\|]{1,2000})\|""",
    """\|product=({app}SmartDashboard)"""
  ]


}
```