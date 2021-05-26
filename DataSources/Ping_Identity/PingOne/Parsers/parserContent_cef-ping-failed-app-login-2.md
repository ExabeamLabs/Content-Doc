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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """end=({time}\d{1,100})""",
    """cat=({category}[^\s]{1,2000})"""
    """request=({outcome}[^\s]{1,2000})""",
    """requestClientApplication=({app}.*?)\s\w+=""",
    """suser=({user}[^\s]{1,2000})""",
    """flexString2=({auth_method}.*?)\s\w+=""",
    """message":"({auth_method}[^\\]{1,2000})\s\\"({device}[^\\]{1,2000})""",
    """msg=({reason}.*?)\s\w+=""",
  ]
}
```