#### Parser Content
```Java
{
Name = cef-securesphere-db-login
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = ArcSight
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF""", """|SecureSphere|""", """cs6=Login""", """cs8=True""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """\srt=({time}\d{1,100})""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sduser=(|(({domain}[^\\\s"]{1,2000})\\+)?({user}[^\\\s"]{1,2000}?))\s{1,100}\w+=""",
    """\scs4=(|({app}.+?))\s{1,100}\w+=""",
    """\scs3=(|({service_name}.+?))\s{1,100}\w+=""",
    """\scs2=(|({server_group}.+?))\s{1,100}\w+=""",
    """\Wcs11=(({domain}[^\\\s"]{1,2000})\\+)?({user}[^\\\s"]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\scs13=(?:|({database_name}.+?))\s{1,100}\w+=""",
    """\scs12=(({domain}[^\\\s]{1,2000})\\+)?({host}[\w\-.]{1,2000})""",
    """\scs14=(|({schema}.+?))\s{0,100}(\w+=|$)""",
    """\ssrc=(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\sspt=({src_port}\d{1,100})""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdpt=({dest_port}\d{1,100})""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\sproto=({protocol}[^\s]{1,2000})"""
  ]
}
```