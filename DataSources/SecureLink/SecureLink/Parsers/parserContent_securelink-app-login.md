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
      """exabeam_host=({host}[^\s]{1,2000})""",
      """connected to Application ({app}[^.]{1,2000})""",
      """AUDIT:.+?\(({user_email}[^@]{1,2000}@({email_domain}[^)]{1,2000}))\)"""
    ]
  }
```