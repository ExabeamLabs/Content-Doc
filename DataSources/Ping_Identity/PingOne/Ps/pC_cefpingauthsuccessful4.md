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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """end=({time}\d{1,100})""",
    """cat=({category}[^\s]{1,2000})"""
    """request=({outcome}[^\s]{1,2000})""",
    """requestClientApplication=({app}.*?)\s\w+=""",
    """suser=({user}[^\s]{1,2000})""",
    """flexString2=({auth_method}.*?)\s\w+"""
    """message":"({auth_method}[^\\]{1,2000})\s\\"({device}[^\\]{1,2000})"""
  ]
}
```