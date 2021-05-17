#### Parser Content
```Java
{
Name = cef-citrix-xenapp-app-login
  Vendor = Citrix
  Product = Citrix XenApp
  Lms = Direct
  DataType = "app-login"
  TimeFormat =  "epoch"
  Conditions = [ """CEF:""", """|Citrix|Cirtix XenApp""", """ rt=""" ]
  Fields = [
    """\sdvc=({host}.+?)\s{1,100}\w+="""
    """\sdvchost=({host}.+?)\s{1,100}\w+="""
    """\scs2=({host}.+?)\s{1,100}\w+=""",
    """\sshost=({src_host}.+?)\s{1,100}\w+="""
    """\srt=({time}\d{1,100})""",
    """\Wsrc=(0.0.0.0|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\Wdst=(0.0.0.0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\sexternalId=({alert_id}.+?)\s{1,100}\w+=""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\|Citrix\|({app}[^\|]{1,2000})\|""",
    """\ssourceServiceName=({app}.+?)\s{1,100}\w+=""",
    """\ssuid=({user_fullname}.+?)\s{1,100}\w+=""",
    """\scs4=({os}.+?)\s{1,100}\w+="""
  ]
}
```