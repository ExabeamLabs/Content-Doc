#### Parser Content
```Java
{
Name = cef-ping-app-login-2
  Vendor = Ping Identity
  Product = PingOne
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName=Ping""", """|login-success|""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """end=({time}\d{1,100})""",
    """cat=({category}[^\s]+)"""
    """request=({outcome}[^\s]+)""",
    """requestClientApplication=({app}.*?)\s\w+=""",
    """suser=({user}[^\s]+)""",
    """flexString2=({auth_method}.*?)\s\w+="""
  ]
}
```