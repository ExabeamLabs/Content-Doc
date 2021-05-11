#### Parser Content
```Java
{
Name = cef-connectra-vpn-login-failed
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = ArcSight
  DataType = "failed-vpn-login"
  TimeFormat = "epoch"
  Conditions = [ """|Check Point|Connectra|""", """|authcrypt_failed|""" ]
  Fields = [
    """\srt=({time}\d{1,100})(\s{1,100}[\w\.:]+=|$)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s{1,100}[\w\.:]+=|$)""",
    """\sdvchost=({host}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\sad.User=({user}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\sad.User=[^=]+?\(({user}[^\(\)]+)\)(\s{1,100}[\w\.:]+=|$)""",
    """\sshost=({src_host}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s{1,100}[\w\.:]+=|$)""",
    """\smsg=({failure_reason}.+?)(\s{1,100}[\w\.:]+=|$)""",
  ]
  DupFields = [ "host->dest_host" , "user->account"]
}
```