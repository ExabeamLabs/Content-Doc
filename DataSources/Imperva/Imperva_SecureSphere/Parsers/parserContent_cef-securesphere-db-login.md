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
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """\srt=({time}\d+)""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\sduser=(|(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+?))\s+\w+=""",
    """\scs4=(|({app}.+?))\s+\w+=""",
    """\scs3=(|({service_name}.+?))\s+\w+=""",
    """\scs2=(|({server_group}.+?))\s+\w+=""",
    """\Wcs11=(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+?)\s*(\w+=|$)""",
    """\scs13=(?:|({database_name}.+?))\s+\w+=""",
    """\scs12=(({domain}[^\\\s]+)\\+)?({host}[\w\-.]+)""",
    """\scs14=(|({schema}.+?))\s*(\w+=|$)""",
    """\ssrc=(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\sspt=({src_port}\d+)""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdpt=({dest_port}\d+)""",
    """\sshost=({src_host}[^\s]+)""",
    """\sproto=({protocol}[^\s]+)"""
  ]
}
```