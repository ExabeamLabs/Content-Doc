#### Parser Content
```Java
{
Name = cef-syslog-securesphere-db-login
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Imperva|SecureSphere DAM|""", """cs5=Login""", """outcome=True""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\scs4=(?: |({app}.+?))\s{1,100}\w+=""",
    """\scs3=(?: |({service_name}.+?))\s{1,100}\w+=""",
    """\scs2=(?: |({server_group}.+?))\s{1,100}\w+=""",
    """\sflexString1=(?: |({database_name}.+?))\s{1,100}\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\sdhost=({dest_host}[^\s]{1,2000})"""
  ]
}
```