#### Parser Content
```Java
{
Name = cef-4723
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-password-change"
  TimeFormat = "epoch"
  Conditions = ["""|Microsoft|Microsoft Windows|""", """An attempt was made to change""" , """externalId=4723"""]
  Fields = [
    """({event_name}An attempt was made to change an account's password)""",
      """\sexternalId=({event_code}\d{1,100})""",
      """\srt=({time}\d{1,100})""",
      """\sdvc=({host}[a-fA-F:\d.]{1,2000})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\ssuser=({user}.+?)\s{1,100}\w+=""",
      """\sduser=({target_user}.+?)\s{1,100}\w+=""",
      """Security_,ID=({user_sid}[^\s]{1,2000}?)(\s|\||$)""",
      """\ssntdom=({domain}.+?)\s\w+=""",
      """\sdeviceSeverity=({outcome}.+?)\s\w+=""",
      """\sdntdom=({target_domain}.+?)\s\w+=""",
      """\sduid=({logon_id}[^\s]{1,2000})""",
      """\sdvc=(?:-|({src_ip}[\w:.]{1,2000}))\s{1,100}\w+="""
    ]
    DupFields = ["host->dest_host"]    


}
```