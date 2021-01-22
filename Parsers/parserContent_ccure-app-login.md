#### Parser Content
```Java
{
Name = ccure-app-login
  Vendor = CCURE
  Product = CCURE
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|C-CURE|""", """|Operator Login"""]
  Fields = [
     """src=({host}[^\s]+)""",
     """\|start=({time}\d+)""",
     """({app}C-CURE)""",
     """\ssuid=(?:Unknown|(({domain}[^\\]+)\\?)?({user}.+?))\s(\w+=|$)""",
     """\ssuser=(?:|({user_fullname}.+?))\s(\w+=|$)"""
	]
}
```