#### Parser Content
```Java
{
Name = ccure-app-login
  Vendor = Tyco
  Product = CCURE Building Management System
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|C-CURE|""", """|Operator Login"""]
  Fields = [
     """src=({host}[^\s]{1,2000})""",
     """\|start=({time}\d{1,100})""",
     """({app}C-CURE)""",
     """\ssuid=(?:Unknown|(({domain}[^\\]{1,2000})\\?)?({user}.+?))\s(\w+=|$)""",
     """\ssuser=(?:|({user_fullname}.+?))\s(\w+=|$)"""
	]
}
```