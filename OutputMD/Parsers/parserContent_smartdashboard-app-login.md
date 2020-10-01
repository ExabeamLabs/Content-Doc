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
    """\|Administrator=({user}[^\|]+)\|""",
    """\|time=({time}\d+\w+\d\d\d\d \d+:\d+:\d+)""",
    """\|client_ip=(?:({src_ip}[a-fA-F\d.:]+)|({src_host}[\w.\-]+))\|""",
    """\|Machine=({host}[^\|]+)\|"""
    """\|Additional Info=({additional_info}[^\|]+)\|""",
    """\|product=({app}SmartDashboard)"""
  ]
}
```