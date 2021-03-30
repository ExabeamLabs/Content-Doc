#### Parser Content
```Java
{
Name = cef-citrix-xenapp-app-login
  Vendor = Citrix XenApp
  Product = Citrix XenApp
  Lms = Direct
  DataType = "app-login"
  TimeFormat =  "epoch"
  Conditions = [ """CEF:""", """|Citrix|Cirtix XenApp""", """ rt=""" ]
  Fields = [
    """\sdvc=({host}.+?)\s+\w+="""
    """\sdvchost=({host}.+?)\s+\w+="""
    """\scs2=({host}.+?)\s+\w+=""",
    """\sshost=({src_host}.+?)\s+\w+="""
    """\srt=({time}\d+)""",
    """\Wsrc=(0.0.0.0|({src_ip}[A-Fa-f:\d.]+))""",
    """\Wdst=(0.0.0.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """\sexternalId=({alert_id}.+?)\s+\w+=""",
    """\ssuser=({user}.+?)\s+\w+=""",
    """\|Citrix\|({app}[^\|]+)\|""",
    """\ssourceServiceName=({app}.+?)\s+\w+=""",
    """\ssuid=({user_fullname}.+?)\s+\w+=""",
    """\scs4=({os}.+?)\s+\w+="""
  ]
}
```