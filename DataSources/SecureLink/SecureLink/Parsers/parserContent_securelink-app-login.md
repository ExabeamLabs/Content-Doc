#### Parser Content
```Java
{
Name = securelink-app-login
    Vendor = SecureLink
    Product = SecureLink
    Lms = QRadar
    DataType = "app-login"
    TimeFormat = "epoch"
    Conditions = [ "SecureLink:","AUDIT:","""connected to Application"""]
    Fields = [
      """exabeam_endTime=({time}\d{1,100})""",
      """exabeam_host=({host}[^\s]+)""",
      """connected to Application ({app}[^.]+)""",
      """AUDIT:.+?\(({user_email}[^@]+@({email_domain}[^)]+))\)"""
    ]
  }
```