#### Parser Content
```Java
{
Name = cef-ping-failed-app-login-2
  Vendor = Ping Identity
  Product = PingOne
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName=Ping""", """|login-failed|"""]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """end=({time}\d+)""",
    """cat=({category}[^\s]+)"""
    """request=({outcome}[^\s]+)""",
    """requestClientApplication=({app}.*?)\s\w+=""",
    """suser=({user}[^\s]+)""",
    """flexString2=({auth_method}.*?)\s\w+=""",
    """message":"({auth_method}[^\\]+)\s\\"({device}[^\\]+)""",
    """msg=({reason}.*?)\s\w+=""",
  ]
}
```