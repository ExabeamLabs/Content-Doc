#### Parser Content
```Java
{
Name = cef-securesphere-db-failed-login
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = ArcSight
  DataType = "database-failed-login"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Imperva Inc.|SecureSphere|""", """cs6=Login""", """cs8=False""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wcs12=(({domain}[^\\\s]+)\\+)?({host}[\w\-.]+)""",
    """\Wduser=(({domain}[^\\\s]+)\\+)?({db_user}[^\s]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wsrc=(0.0.0.0|({src_ip}[A-Fa-f:\d.]+))""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wproto=({protocol}[^\s]+)""",
    """\Wcs2=\s{0,100}(|({server_group}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs3=(|({service_name}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs4=(|({app}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs11="{0,20}(({domain}[^\\\s",]+)\\+)?({user}[^\\\s",]+)"{0,20}\s{0,100}(\w+=|$)""",
    """\Wcs13=(|({database_name}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs14=(|({schema}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs18=(|({reason}.+?))\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "db_user->account" ]
}
```