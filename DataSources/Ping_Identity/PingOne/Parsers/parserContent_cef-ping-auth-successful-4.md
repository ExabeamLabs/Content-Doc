#### Parser Content
```Java
{
Name = cef-ping-auth-successful-4
  Vendor = Ping Identity
  Product = PingOne
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName=Ping""", """flexString2=SSO""", """request=Success""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """end=({time}\d{1,100})""",
    """cat=({category}[^\s]+)"""
    """request=({outcome}[^\s]+)""",
    """requestClientApplication=({app}.*?)\s\w+=""",
    """suser=({user}[^\s]+)""",
    """flexString2=({auth_method}.*?)\s\w+"""
    """message":"({auth_method}[^\\]+)\s\\"({device}[^\\]+)"""
  ]
}
```